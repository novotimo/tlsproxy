# tlsproxy

[![CMake Build and Test](https://github.com/novotimo/tlsproxy/actions/workflows/cmake-debug-test.yml/badge.svg)](https://github.com/novotimo/tlsproxy/actions/workflows/cmake-debug-test.yml)
[![Coverage](https://raw.githubusercontent.com/novotimo/tlsproxy/badges/coverage.svg)](https://github.com/novotimo/tlsproxy/actions/workflows/coverage.yml)

A TLS termination proxy for services that do not speak TLS. It accepts the TLS
connection, forwards the decrypted bytes to your server over plain TCP, and
never looks at them, so it works for any protocol that runs over TCP rather than
only HTTP.

About 2,950 lines of C99 on an epoll event loop with an nginx-style
master/worker model. The only runtime dependencies are OpenSSL and libcyaml.

```sh
docker run --name tlsproxy \
    --volume ${PWD}/example-docker/config/:/etc/tlsproxy:ro \
    --publish 443:8443 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    novotimo/tlsproxy:latest
```

## What you get

- **Any TCP protocol.** No HTTP parser anywhere in the program. MQTT, a game
  server, an RPC service, a database, `telnets` if you must.
- **No capabilities.** The image runs as UID 2001 and is never root, so there is
  no privilege to drop and no window in which it holds one. It listens on 8443
  inside the container and lets Docker publish 443, so it does not need
  `NET_BIND_SERVICE` either. The shipped compose file is `cap_drop: ALL` with
  nothing added back, plus `read_only`, `no-new-privileges` and explicit pid,
  memory and descriptor limits.
- **Reload without dropping connections.** `SIGHUP` re-reads the config file.
  One that does not parse, does not pass validation, or names a certificate that
  will not load leaves the running configuration untouched.
- **Logs a log analyser can read.** Every line is logfmt, every event has a
  type, and anything a client can influence is escaped, so nobody injects a
  record by putting a newline in a hostname.
- **Several listeners in one process,** each with its own backend, certificate
  chain and timeouts. Point two at the same address and port with different
  backends and `SO_REUSEPORT` spreads connections across them by 4-tuple hash,
  which is rough load balancing for free. It is random rather than
  least-connections, so it will not replace haproxy.
- **IPv4 and IPv6,** binding dual-stack with `IPV6_V6ONLY` off.

## Numbers

Against nginx and haproxy on the same host, same OpenSSL, same certificate,
groups and ciphersuite, logging off in all three, eight workers each on four
physical cores. These are the columns where tlsproxy comes out ahead; the full
set, including where it does not, is in
[`benchmark/BASELINE.md`](benchmark/BASELINE.md).

| | tlsproxy | nginx | haproxy |
| --- | --- | --- | --- |
| Memory, 20,000 held connections | **906 MB** | 1,443 MB | 1,112 MB |
| Memory, 1,000 held connections | **78 MB** | 307 MB | 113 MB |
| Message p99, 20,000 held connections at one message a second | **2.7 ms** | 831 ms | 657 ms |
| Handshakes a second, 1,024 concurrent | **10,313** | 10,154 | 9,481 |
| Throughput, 64 KB payloads | **2,221 MB/s** | 2,162 MB/s | 1,791 MB/s |
| Failed connections, all sweeps | **0** | 0.19% at 4,096 concurrent | 0.005% throughout |

nginx is a few percent ahead on handshake rate below 1,024 concurrent and on
1 MB payloads, and holds a lower p99 once the offered handshake rate passes
10,000 a second.

Read the caveats before quoting any of it: the per-subject tuning sweeps have
not been run, so nginx and haproxy are on settings I chose rather than their
own best, and only the ECDSA certificate has been measured. Everything needed to
re-run it is in [`benchmark/`](benchmark/README.md), including the harness, the
committed CSVs and a profiler.

## Try it

The full demo brings up a proxy on 443 in front of an nginx backend over a
Docker network, so you can point a browser at https://localhost. The certificate
is a self-signed test one, so the browser will object.

```sh
cd example-docker
docker compose up
```

For your own backend, take the config and certificates from
`example-docker/config/`, point `target-ip` and `target-port` at your service,
leave `listen-port` at 8443, and publish whatever you like on the outside with
the `docker run` at the top of this page.

## Configuration

One YAML file, `/etc/tlsproxy/tlsproxy.yml` by default or named on the command
line. [`example/default.yml`](example/default.yml) is commented throughout and
doubles as the reference: worker count, log file and level, then a list of
listeners, each with a backend, a listen address, a certificate chain, a connect
timeout, TCP keepalive and shutdown deadlines. The keepalive, shutdown and
connect timeout keys are optional and an absent one takes the default named
beside it. Every timeout is in seconds.

`nworkers` wants to be the number of hardware threads you are giving it. Half
that leaves half the machine idle, and measurably so.

What a listener sends is the server certificate and the intermediates above it,
with the root left out, since a client that doesn't already trust the root gains
nothing from a copy of it and one that does has it already. Named individually
in `cacerts` the intermediates are put in order for you and anything not on the
path up from `servcert` draws a warning and stays behind. One certificate per
file there, since we read the first one in each and stop, so a bundle needs
splitting up before it goes in the list and nothing will tell you if it didn't.
Given instead as one `cert-chain` file they go out as written, leaf first and
each issuer after the certificate it signed, since that path sends the file
rather than sorting it.

Nothing verifies any of that. No path is built against a trust store, no
signature is checked and no expiry is looked at, so a chain with a link missing
starts here and is refused at the client instead. The one check at startup is
OpenSSL's, that `servkey` belongs to the certificate being served, and it is a
refusal to start. A self-signed certificate on its own in `cert-chain` is
therefore an ordinary configuration rather than a special case, and is how to
run this without a CA at all.

**`SIGHUP` reloads the configuration.** The master re-reads and re-validates the
file, and only then tells the workers to cycle, so a file with a bad port, an
`nworkers` of zero, a `tcp-keep*` above what the kernel accepts, or a
`cert-chain` given together with `cacerts` is rejected with the name of the
listener it came from and the running configuration carries on. The same checks
run at startup, where they go to stderr instead of the log.

The private key's file mode is checked as a warning rather than a requirement,
since a mode that is wrong in one deployment is deliberate in another. A
`servkey` that group or other can read, write or execute draws a line at startup
and on every reload.

## Building

Needs OpenSSL 3.x and [libcyaml](https://github.com/tlsa/libcyaml) 1.4.2, which
does not use CMake, so install it their way first. CMocka and Doxygen are
optional, for the tests and the docs.

```sh
cmake -B build
cmake --build build
```

If cmake reports that libcyaml was not found, it has installed itself under
`/usr/local` and pkg-config is not looking there:

```sh
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

Two vendored files in `external/` need nothing from you: nginx's red-black tree
and [Verstable](https://github.com/JacksonAllan/Verstable) for the closed set.

## Roadmap

- Configurable TLS: groups including the post-quantum hybrids, ciphersuites,
  version range, and the negotiated group logged (#44).
- Handshake, idle and connection-lifetime timeouts, which is what bounds a
  client that connects and goes quiet (#54).
- Descriptor exhaustion: raise `RLIMIT_NOFILE`, survive `EMFILE`, add
  `max-connections`, then measure the real ceiling (#45).
- Client certificate verification (#17).
- A security model section in `doc/ARCHITECTURE.md`: the trust boundary, what
  enforces each part of it, and what is deliberately out of scope (#55).
- A session cache in the shared memory that is already there (#11).
- Bulk throughput above a 16 KB payload, which is where it stops scaling (#71).
- Re-resolve backend addresses, so a backend that moves is noticed without
  cycling workers (#9).
- Privilege separation for the private key, so a worker compromise is not a key
  disclosure.

## Documentation

- [`doc/ARCHITECTURE.md`](doc/ARCHITECTURE.md), the design and why it is that
  shape
- [`TESTING.md`](TESTING.md), running the suite and how it is written
- [`benchmark/README.md`](benchmark/README.md), the benchmark method
- [`CHANGELOG.md`](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).
