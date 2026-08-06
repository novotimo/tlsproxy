# tlsproxy

[![CMake Build and Test](https://github.com/novotimo/tlsproxy/actions/workflows/cmake-debug-test.yml/badge.svg)](https://github.com/novotimo/tlsproxy/actions/workflows/cmake-debug-test.yml)
[![Coverage](https://raw.githubusercontent.com/novotimo/tlsproxy/badges/coverage.svg)](https://github.com/novotimo/tlsproxy/actions/workflows/coverage.yml)

This is a TLS termination proxy. It sits in front of a server that doesn't speak
TLS, terminates the TLS connection itself, and forwards the decrypted bytes to
that server over a plain TCP connection. It never interprets those bytes, so it
works for any protocol that runs over TCP rather than just HTTP.

It's about 2,700 lines of C99 on an epoll event loop, with an nginx-style
master/worker process model. The only runtime dependencies are OpenSSL and
libcyaml.

## What it's for

The intended user is someone running a service that doesn't do TLS well, or at
all: an RPC server, a database, an MQTT broker, a game server. nginx and haproxy
will both do this job and do it well, but they're large programs, and most of
what they contain is HTTP machinery you aren't using if all you want is a
tunnel. In scope this is much closer to stunnel, just built on an event loop
instead.

In more detail:

- **Any TCP protocol.** There's no HTTP parser in this program at all. Take the
  commented-out `telnets` listener in `example/default.yml` as proof that the
  proxy doesn't touch your bytes.
- **A container with no capabilities.** The image runs as UID 2001 and is never
  root, so there's no privilege to drop and no window during which it holds one.
  It listens on 8443 inside the container and lets Docker publish 443, so it
  doesn't need `NET_BIND_SERVICE` either. The shipped compose file is
  `cap_drop: ALL` with nothing added back, along with `read_only: true`,
  `no-new-privileges`, a pids limit, a memory limit and an explicit nofile
  ulimit.
- **Configuration reload with a dry run.** A config file that doesn't parse,
  doesn't pass the same validation startup applies, or names a certificate that
  doesn't load, leaves the running configuration alone. See "Configuration
  reload" below for how that works.
- **Logs meant for a log analysis system.** Every line is key-value (logfmt),
  every event has a type, and anything a client can influence is escaped before
  it goes in, so nobody gets to inject a log record by putting a newline into a
  hostname.
- **Multiple listeners in one process,** each with its own backend, certificate
  chain and timeouts. If you point two listeners at the same address and port
  with different backends, `SO_REUSEPORT` means the kernel spreads new
  connections across them by 4-tuple hash, which gives you rough load balancing
  for free. It's random rather than least-connections, so it won't replace
  haproxy, but for two equivalent backends it does the job.
- **IPv4 and IPv6,** since listeners bind dual-stack with `IPV6_V6ONLY` turned
  off.

## How it works

`doc/ARCHITECTURE.md` has the full design; this is a summary of the main
decisions.

### The proxy context and tagged pointers

Each connection pair is one `proxy_t`, holding both file descriptors, both
buffer queues and the state machine. Both descriptors go into epoll carrying a
pointer to that same context, which raises the question of how you tell the two
events apart. `malloc` aligns to an 8-byte boundary, so the bottom 3 bits of the
pointer are free, and we set bit 0 on the client descriptor:
`uint8_t tag = (uintptr_t)event & 0x1`. The dispatcher masks the tag off and
passes it along without knowing what it means, and `handle_proxy()` is where it
gets interpreted. That's one allocation per connection pair and no lookup table.

### Freed contexts within an epoll batch

`epoll_wait()` returns a batch of events. If handling one of them tears down a
connection and frees the `proxy_t`, any later event in the same batch is still
carrying that freed pointer, and dereferencing it is a use-after-free that only
shows up under load.

Each worker keeps a hash set of the pointers it has freed during the current
batch. Dispatch checks the set before handling an event, teardown inserts into
it, and the set is cleared once the batch is done. It's keyed on the untagged
pointer so both descriptors of a pair resolve to the same entry.

### Timeouts

Timeouts live in a red-black tree, which is what nginx does and for the same
reason: the nearest deadline is the leftmost node, so working out the
`epoll_wait()` timeout is O(log n) and expiring is a walk from the left until
you reach one that hasn't fired. The tree itself is nginx's, vendored into
`external/`, since theirs is good and mine wouldn't have been better.

### Logging

Workers never touch the log file. A worker formats its line into a private
buffer, takes a `PTHREAD_PROCESS_SHARED` mutex, copies the line into a 64K ring
buffer in an anonymous mmap shared across the whole process tree, and then bumps
an eventfd. The master's epoll loop wakes on that eventfd and does the write. So
no worker ever blocks on disk, and the file has exactly one writer, which means
lines can't interleave.

The mutex is robust. If a worker dies while holding it, the next worker to take
it gets `EOWNERDEAD` and calls `pthread_mutex_consistent()` rather than hanging.
Without that, one dead worker would deadlock every other worker permanently, and
killing them wouldn't release it. When the ring buffer is full we drop lines and
say so once, instead of blocking, since a logger that can stall the data path
under load is worse than one that loses a line.

An audit event looks like this:

```
timestamp=2026-08-05T00:54:52+1000 service=tlsproxy process_type=master pid=101274 level=INFO event=cert_loaded cert_role="leaf" cert_fingerprint="ddf365cdf655c23a75506c7fea161a4f081526cabbdd70831d7053def004cf6c" cert_notbefore="2025-12-15T14:18:32+0000" cert_notafter="2035-09-14T14:18:32+0000" cert_subject="/C=MX/ST=Durango/L=Durango/O=Dingo/OU=Development/CN=Test Server" cert_issuer="/C=MX/ST=Durango/L=Durango/O=Dingo/OU=Development/CN=Test Intermediate"
```

Handshakes are logged with the client address, the listener, the negotiated
ciphersuite and the outcome, which is one of granted, denied or failed.

### Configuration reload

On SIGHUP the master parses the new config file, runs it through the same
validation startup uses, and then builds a complete `SSL_CTX` for every listener
in it, loading every certificate and key. We don't
use those contexts for anything; we build them only to prove that they can be
built, and then free them. Only once all of that has succeeded does the master
swap in the new configuration and cycle the workers. Point `servcert:` at a file
that doesn't exist and send SIGHUP, and the proxy carries on serving traffic
under the old configuration and logs what was wrong with the new one.

Reload runs entirely in the master, which owns no listeners of its own, so
there's no window where a worker is reading a configuration that's being freed.

### Shutdown

When either side of a connection closes, the proxy works through
`PS_SERVER_DISCONNECTED`, `PS_CLIENT_FLUSHED` and `PS_CLOSE_NOTIFY_SENT`,
flushing whatever is still queued for the other side, sending `close_notify` and
then leaving. It deliberately doesn't wait for the peer's `close_notify` in
reply, because a peer that never answers would otherwise pin the context, both
descriptors and the worker's connection count for as long as it liked.

Once we're done with a connection we keep reading from the client and throwing
it away until it stops, since closing a socket with data still sitting in its
receive queue sends a RST rather than a FIN; nginx calls this
`lingering_close`. Two per-listener keys bound it, `shutdown-timeout` for the
whole teardown and `shutdown-interval` for the gap between client messages,
defaulting to 30 and 5 seconds.

### Hardening

```
$ checksec --file=build/tlsproxy
RELRO         STACK CANARY   NX           PIE           RPATH     RUNPATH      FORTIFY
Full RELRO    Canary found   NX enabled   PIE enabled   No RPATH  No RUNPATH   Partial (4/8)
```

That comes from `-fstack-protector-strong`, `-fstack-clash-protection`,
`-fcf-protection=full`, `-ftrivial-auto-var-init=zero`, `-D_FORTIFY_SOURCE=3`,
full RELRO with `BIND_NOW` and PIE, applied through GCC's `-fhardened` where
it's available and spelled out flag by flag where it isn't. On the TLS side we
set a minimum version of TLS 1.2, `SSL_OP_NO_RENEGOTIATION` and
`SSL_OP_CIPHER_SERVER_PREFERENCE`.

Our own code compiles under `-Wall -Wextra -Wshadow -Wsign-conversion
-Wpointer-arith -Wstrict-prototypes -Wwrite-strings -Wimplicit-fallthrough=5
-Werror`, at `-O2`, with nothing left over. Vendored headers are excluded from
that, since they're not ours to fix.

## Testing

153 tests across six binaries, all passing:

```sh
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DUNIT_TESTING=y
cmake --build build
ctest --test-dir build --output-on-failure
```

The suites mock at the libc and OpenSSL boundary using `-Wl,--wrap`, and the
mocks record the arguments they were called with rather than only faking a
return value. That distinction is the whole reason the suite was rewritten: it
reached 100% line coverage in December 2025 and still missed ten defects,
because the old mocks discarded their arguments, so a leaked file descriptor or
a NULL passed to the logger couldn't be expressed as a test at all. Tests are
named after the claim they make, so a failure of
`handle_accept_closes_fd_when_ssl_new_fails` is already the bug report.

CI runs five jobs on every push to every branch:

| Job | Purpose |
| --- | --- |
| Unit tests (Debug) | The suites at `-O0`, with asserts live |
| Release build (`-Werror` at `-O2`) | Warnings that only appear with optimization on, and the only build compiled with `NDEBUG` |
| ASAN + UBSAN | Gates on sanitizer diagnostics rather than exit code, since UBSAN reports and continues |
| Valgrind memcheck | Uninitialized reads, which ASAN doesn't see |
| Coverage | Line coverage over `src/`, with a floor enforced |

The coverage floor is there to stop the suite silently rotting back to where it
was, rather than as a number to chase; the December 2025 result above is why.

## Try it out

### Full demo

Download the `example-docker/` folder, cd into it, and run:

```sh
$ docker compose -f compose.yml up
```

That gives you a proxy on port 443 forwarding to an nginx HTTP server over a
Docker network, so you can point a browser at https://localhost. The certificate
chain is a self-signed test one, so your browser will object to it.

### With your own backend

```sh
$ docker pull novotimo/tlsproxy:latest
```

Take the config and certificates from `example-docker/config/`, point
`target-ip` and `target-port` at your service, leave `listen-port` at 8443 and
publish whatever you like on the outside:

```sh
$ docker run --name tlsproxy \
      --volume ${PWD}/example-docker/config/:/etc/tlsproxy:ro \
      --publish 443:8443 \
      --cap-drop ALL \
      --security-opt no-new-privileges:true \
      novotimo/tlsproxy:latest
```

There's no `--cap-add` in there because the proxy doesn't need one. For
comparison, the nginx container sitting next to it in
`example-docker/compose.yml` needs `CHOWN`, `SETGID` and `SETUID` given back so
that it can drop to its own user.

## Configuration

One YAML file. `example/default.yml` is commented throughout and doubles as the
reference: worker count, log file and level, and then a list of listeners, each
with a backend, a listen address, a certificate chain, a connect timeout, TCP
keepalive settings and the shutdown deadlines above. The keepalive, shutdown
and connect timeout keys are all optional, and an absent one takes its default,
which the example names in the comment beside it. Every timeout in there is in
seconds.

What the schema can't express is checked after parsing, so a port outside 1 to
65535, an `nworkers` of zero or above 128, a `tcp-keep*` value above what the
kernel will accept, and a `cert-chain` given together with `cacerts` are all
refused with the name of the listener they came from. The same checks run on
reload, where they go to the log instead of stderr.

Run it as `./tlsproxy <config.yml>`, or with no argument at all, in which case
it reads `/etc/tlsproxy/tlsproxy.yml`. That's what the Docker image does.

## Building

### Dependencies

- OpenSSL 3.x
- [libcyaml](https://github.com/tlsa/libcyaml), built against 1.4.2. It doesn't
  use CMake, so install it their way first.
- CMocka, optional, for the tests
- Doxygen, optional, for the docs

Two vendored files live in `external/` and need nothing from you: nginx's
red-black tree, and [Verstable](https://github.com/JacksonAllan/Verstable)
(commit [`dd83033`](https://github.com/JacksonAllan/Verstable/commit/dd83033fb72736a1d2332e43b84b7794b5d19635))
for the closed set.

If your OpenSSL is 3.5 or newer you inherit its default group list, which
includes the X25519MLKEM768 post-quantum hybrid. That's OpenSSL's doing rather
than ours, though; see "What isn't done yet" before repeating it anywhere.

### Build

```sh
cmake -B build
cmake --build build
```

Everything lands in `build/`.

If cmake reports `The following required packages were not found: - libcyaml`,
then libcyaml has installed itself under `/usr/local` and pkg-config isn't
looking there:

```sh
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

To build the tests, `-DCMAKE_BUILD_TYPE=Debug` alongside `-DUNIT_TESTING=y` is
not optional. `UNIT_TESTING` forces `-O0`, and `_FORTIFY_SOURCE` at `-O0` makes
glibc emit a warning that `-Werror` then turns into a build failure.

## What isn't done yet

This is version 1.1.0, and these are the gaps I know about. `CHANGELOG.md`
covers what changed since 1.0.0, which was mostly repair work.

- **There are no benchmarks published.** There used to be a graph here, and I've
  taken it down. Going back over the methodology I found at least five ways it
  was unfair to nginx, the worst being that nginx wrote around 9 million access
  log lines during the run while we wrote none, and that nginx was in HTTP
  reverse-proxy mode with connection pooling while we were opening one backend
  connection per client connection. It also wasn't reproducible, since no run
  command was recorded anywhere. I'm redoing it properly: matched certificates,
  groups, ciphers and logging settings, stream mode against stream mode,
  several runs reported as medians, and the CSV and plotting script committed
  so the numbers can be regenerated. It goes back in when that exists.
- **The concurrency ceiling hasn't been measured.** I'm not going to write "tens
  of thousands of connections" until I've hit the wall and can say where it is.
  There are three concrete reasons it isn't there yet: `RLIMIT_NOFILE` isn't
  raised at startup, an `EMFILE` from `accept()` isn't handled gracefully, and
  there's no `max-connections` option to reject cleanly with.
- **There's no handshake timeout and no idle timeout.** The only timeout wired
  into the red-black tree is the backend connect, along with the shutdown
  deadlines. A client that finishes the TCP handshake and then goes quiet is
  bounded by TCP keepalive and nothing else, which isn't a real answer to
  slowloris. The infrastructure is all there, so this is wiring rather than
  design.
- **TLS is barely configurable.** You configure certificates and keys, and
  that's it. There's no way to set groups, ciphersuites or the version range,
  and we don't log which group was negotiated, so the proxy can't currently even
  tell you whether that post-quantum hybrid above was used. That's
  `SSL_CTX_set1_groups_list()` and friends, and it's the next thing I'm doing.
- **There's no client certificate verification.** `cacerts:` builds the chain we
  offer to clients; it doesn't verify anybody. mTLS is on the roadmap rather
  than in the program.
- **Workers hold the private key and parse untrusted input in the same address
  space,** so a worker compromise is a key disclosure. In-process privilege
  separation is what fixes that properly and it's on the roadmap. nginx and
  haproxy both have the same property, so this isn't a gap against the
  alternatives, but it is a gap.
- **The backend address is resolved once, at worker startup,** so if a backend
  moves, workers won't notice until they're cycled. That matters more under
  Docker, not less.
- **There's no privilege dropping or chroot, deliberately.** The container is
  the boundary. Mount namespaces are a stronger answer than chroot, which was
  never a security boundary on its own, and starting as a non-root user is
  stronger than dropping root after binding, since there's no window in which we
  hold it. If you run this outside a container, put it behind a systemd unit
  with the equivalent settings.

## Roadmap

1. Configurable TLS: groups including the hybrid PQC ones, ciphersuites, version
   range, and the negotiated group logged alongside the ciphersuite.
2. Handshake and idle timeouts, and an optional cap on connection lifetime.
3. File descriptor exhaustion: raise `RLIMIT_NOFILE`, handle `EMFILE` without
   spinning, add `max-connections`, and then measure the real ceiling.
4. A warning at startup when the private key file is group- or world-readable,
   which is the last of the configuration checks in #46 still outstanding.
5. The benchmark rebuild described above.
6. A security model section in `doc/ARCHITECTURE.md` covering the trust
   boundary, what enforces each part of it, and what's deliberately out of
   scope.

After those: mTLS, privilege separation for the private key, re-resolving
backend addresses, and a session cache in the shared memory that's already
there.

## License

MIT. See [LICENSE](LICENSE).
