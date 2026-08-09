# Benchmark

This is the methodology for the tlsproxy benchmark: what gets measured,
against what, and under which controls. It was written before the harness and
before any numbers, since the previous benchmark had its method reconstructed
after the graph was already published and most of what was wrong with it
followed from that ordering.

## Results

The reference numbers are in `BASELINE.md`, rendered from the CSVs in
`baseline/` by `python3 report.py baseline/`, measured at `6e847f2`. They are
a **baseline for before-and-after comparison, not a published result**: the
per-subject tuning sweeps described
below have not been run, so nginx and haproxy are on settings I chose rather
than their own best, and only the ECDSA certificate has been measured. Nothing
from them should go into the project README until that is done.

## The previous benchmark

The README used to carry an apib graph showing 9.1 million requests for nginx
against 18.4 million for tlsproxy over five minutes, with bandwidth and memory
figures beside it. It came down in August 2026. Its faults are listed here
because each control further down is an answer to one of them:

- nginx wrote about 9.1 million access log lines during the run and tlsproxy
  wrote none.
- nginx was in HTTP reverse-proxy mode with upstream connection pooling, while
  tlsproxy opens one backend connection per client connection. Those are
  different jobs.
- nginx negotiated P-256 and tlsproxy negotiated X25519, so the key exchange
  was not the same.
- nginx had HTTP/2 on through ALPN and tlsproxy negotiates no ALPN at all, so
  the two may not have been speaking the same protocol.
- The memory comparison, 34MB plus 700MB of cache against 69MB, mixed two
  metrics.
- Prometheus, cAdvisor, Grafana and node-exporter were running unconstrained on
  the host being measured.
- `compose.yml` referred to a `tlsproxy:latest` with no `build:` stanza, and no
  run command was recorded anywhere, so nobody could reproduce it, including
  me.

## Subjects and tests

Three subjects: tlsproxy built from the repository at the SHA in the
provenance block, nginx, and haproxy. Three tests, and the middle one is
expected to lose.

### Test A: stream mode

nginx `stream {}`, haproxy `mode tcp` and tlsproxy unchanged, all three doing
the one job: terminate TLS, open a backend connection per client connection,
forward bytes, parse nothing. This is the only like-for-like comparison
available and it carries the headline.

There are two backends, chosen by what the client sends. The tests that speak
HTTP over the tunnel use an nginx instance serving a fixed-size body. The
handshake test does not send anything, and there an HTTP server is the wrong
backend: it holds every abandoned connection for `client_header_timeout` and
then closes connections the proxy is still using, so what gets measured is the
backend's reaping policy. Measured on this harness, that alone moved nginx
between 5,149 and 8,918 handshakes a second and put failures on the subject
with the longest latency tail. So the handshake test runs against
`backend/sink`, which accepts, holds, closes only when the peer closes, and has
no timeout of any kind.

### Test B: HTTP mode

nginx and haproxy in HTTP mode with upstream keepalive against the same
backend, and tlsproxy unchanged because it has no other mode. Reusing a pooled
backend connection is a better design for HTTP than opening a new one per
request, so this is where the numbers should go against us. It is published
anyway, since the difference it measures is real and somebody deciding whether
to put this in front of an HTTP service should see it.

Upstream connection reuse is the single variable. Both nginx and haproxy run
HTTP/1.1 with h2 not advertised, so the wire protocol is the same across all
three and the pooling is what differs. The old benchmark's HTTP/2 mismatch is
the fault being corrected there.

### Test C: byte tunnel

Test A's configuration with the HTTP backend replaced by a discard/echo sink
and the HTTP client replaced by a small TLS client that opens a connection,
sends a fixed payload and reads the reply. No HTTP anywhere. This is the case
tlsproxy exists for, and it is the only one of the three whose shape is not set
by an HTTP client's behaviour.

## Topology

Two topologies, and every graph says which one it came from.

**Cross-host.** The subject runs on the Linux machine and the load generator on
the other one, over wired Ethernet with the negotiated link speed in the
provenance block. This carries the handshake rate, the latency percentiles and
the concurrency and memory sweeps, all of which are bounded by connection count
and packet rate rather than by bandwidth.

**Same-host.** Subject and generator on the one machine, on disjoint cpusets,
over loopback. This carries the bulk transfer sweep, because AES-256-GCM runs
at about 6.06 GB/s on one core of the i7-11850H (`openssl speed -evp
aes-256-gcm -bytes 8192`, OpenSSL 3.5.7) while a gigabit link carries 0.125
GB/s, so a bulk transfer test across the wire would be a measurement of the
NIC. Loopback takes the link out, and the disjoint cpusets are what keeps the
generator off the subject's cores.

The subject sits on the machine with a native Docker, since the controls above
need per-subject `cpus`, `mem_limit` and `ulimits.nofile`, which is a cgroup
the daemon owns. Docker Desktop on Windows runs that daemon inside a virtual
machine and forwards published ports through a relay on the Windows side, and a
subject behind those two layers would mostly be measuring them.

The generator sits on the other machine because a full handshake costs the
client roughly what it costs the server and sometimes more: one core of the
i7-11850H does 33,851 ECDSA P-256 signatures a second against 10,888
verifications, so with an ECDSA certificate the client does the expensive half,
and an under-provisioned generator would set the ceiling instead of the
subject. The headroom check below is what catches that when it happens anyway.

That machine boots a Linux live image rather than an installed system, so
nothing is installed on it and every run starts from the same state. The two
generators are built ahead of time on the subject host and copied across:
`tlsload`, `tls-perf` and `wrk2` are epoll programs that link `libssl.so.3`,
`libcrypto.so.3` and glibc 2.38 or newer and nothing else once `tls-perf` is
linked `-static-libstdc++ -static-libgcc`, all of which any current live image
carries. They are built at `-march=x86-64-v2` rather than at the `-march=native`
in tls-perf's own Makefile, since the build host has AVX-512 and the generator
host does not, and a binary that assumes otherwise dies on the first
instruction it cannot execute.

## Fairness controls

The rule is to match the workload, not the implementation. The certificate,
group, ciphersuite, protocol version, resumption policy, concurrency, backend,
CPU budget and memory budget define the job and are identical across subjects.
What each subject does inside those bounds is whatever its own project would
recommend, found by sweeping its own tuning knobs, since forcing three
different architectures onto one set of internal settings handicaps whichever
of them the settings suit least and calls it fairness.

| Control | How it is held |
| --- | --- |
| Logging | Off on all three for the headline runs. One variant of the handshake test runs with logging on for all three and records lines written per connection for each subject, so that the comparison is measured rather than assumed. |
| Certificate | ECDSA P-256 and RSA-2048, run separately, the same two files for all three subjects. RSA-4096 is not run, since it is unrepresentative of deployed certificates and moves handshake cost by an order of magnitude, which would swamp everything else on the graph. |
| Groups | The client offers exactly one group, so all three servers select the same one. |
| Ciphers | The client offers exactly one ciphersuite, on the same principle. |
| TLS version | The client offers TLS 1.3 only for the headline. A TLS 1.2 variant runs separately. |
| Resumption | Off for the handshake tests, enforced at the client, which starts every connection with no session and no ticket. The throughput tests state their setting per graph. |
| ALPN | Nothing negotiated, on all three. tlsproxy installs no ALPN callback, so this is the only setting the three can hold in common. Test B is HTTP/1.1 with h2 not advertised. |
| Backend model | Tests A and C: one backend connection per client connection everywhere, no pooling. Test B: pooling on nginx and haproxy, which is the difference under test. |
| Workers | The same count on all three, all pinned to the same cpuset. haproxy is threads in one process where nginx and tlsproxy are processes, so it is the count that is matched and not the mechanism. |
| Runtime | All three subjects run Debian 13 with the same glibc and the same libssl3 package, built from `subjects/nginx/Dockerfile` and `subjects/tlsproxy/Dockerfile` where the published images do not already match. The images each project publishes otherwise differ in both: nginx-alpine carried musl and OpenSSL 3.5.5 against haproxy's glibc and 3.5.7. Measured here, moving nginx from musl to glibc alone moved it about 17%, which is larger than most of what is under test, so leaving it uncontrolled would have swamped the result. |
| Load model | Stated per graph. A closed-loop generator holds a fixed number of connections and starts a new one only as an old one finishes, so it never offers more load than the subject can absorb and a slow subject simply receives less work. An open-loop generator fixes the arrival schedule in advance, so a slow subject accumulates a queue and then sheds. Capacity graphs use the closed model, and the graphs that describe behaviour under load use the open one. |
| Per-subject tuning | Each subject's own knobs are swept before a published run and its best result is the one reported, so a win is against a tuned opponent rather than a default one. |
| Container limits | Explicit `cpus`, `mem_limit` and `ulimits.nofile` on every subject, at the same values. nginx's `worker_connections` and `worker_rlimit_nofile` and haproxy's `maxconn` are raised past the ceiling under test, so that no subject stops at a limit of its own. |
| Load generator | A separate host from the subject for every test except the bulk transfer sweep, which runs on the subject host on a disjoint cpuset for the reason under "Topology". |
| Monitoring | No Prometheus, cAdvisor, node-exporter or Grafana on either host during a measured run. The harness samples the cgroup files directly into CSV. |
| Repetition | Six runs per point, the first discarded since it follows a container start, reported as median and inter-quartile range over the remaining five. No single-run numbers. The repetitions for a point run consecutively rather than interleaved across subjects, so a slow drift would land on one subject rather than spread over the three; the CPU and throttle columns on every row are what would expose that. |
| Memory metric | Working set, `memory.current` minus `inactive_file` from the subject's cgroup, which is the quantity cAdvisor publishes as `container_memory_working_set_bytes`. The same metric for all three. A peak only means something for a subject whose memory tracks connections held; where it tracks connections completed the peak is just the run duration times a slope, so what gets published there is the slope and the ceiling it reaches. |
| Provenance | Kernel, Docker version, CPU model, core count, RAM, NIC and negotiated link speed, every tool version, and the tlsproxy git SHA, recorded into every result file. |

### TLS parameters at the client

`app/main.c:init_openssl()` sets a TLS 1.2 minimum,
`SSL_OP_IGNORE_UNEXPECTED_EOF`, `SSL_OP_NO_RENEGOTIATION` and
`SSL_OP_CIPHER_SERVER_PREFERENCE`, and inherits every other OpenSSL default.
There is no configuration for groups, ciphersuites, the version range or
session caching, which is issue #44, and it is not being fixed for the
benchmark's convenience. So every parameter that has to match across the three
subjects is pinned at the client instead: a client offering exactly one group,
one ciphersuite and one protocol version leaves all three servers with the same
single choice, whatever their own preference order would otherwise have said.
The limit of doing it that way is that server preference goes untested, so
`SSL_OP_CIPHER_SERVER_PREFERENCE` has nothing to express and nginx's and
haproxy's cipher ordering is equally moot.

Each control is one `tlsload` flag reaching the OpenSSL call that enforces it:
`-G` is `SSL_CTX_set1_groups_list()`, `-V` sets the minimum and the maximum
protocol version to the same value, and `-k` goes to
`SSL_CTX_set_ciphersuites()` for TLS 1.3 or `SSL_CTX_set_cipher_list()` for
TLS 1.2, which are separate knobs that a client conflating them would silently
fail to hold. `tls-perf` holds the same four and is kept as a cross-check on
the handshake numbers, since a generator that agrees with an independent one is
worth more than a generator that only agrees with itself.

Resumption is off unless `-R` is given, which is `SSL_OP_NO_TICKET` plus a
disabled client session cache. It matters here that
the control is at the client, since tlsproxy has no session cache configuration
and `app/main.c:main()` builds every `SSL_CTX` before the fork, so what the
workers do about tickets is whatever OpenSSL's defaults do. A client that starts
every connection with no session and no ticket gets a full handshake from all
three regardless.

### The two certificates

The two certificate types put the cost on opposite sides of the connection,
which is why both are run. One core of the i7-11850H, taken with `taskset` onto
a core in the subject's own cpuset and with the governor and turbo pinned the
way a run pins them, so these describe the machine under test rather than the
same machine boosting:

| Operation | Per second |
| --- | --- |
| ECDSA P-256 sign, which the server does | 33,851 |
| ECDSA P-256 verify, which the client does | 10,888 |
| RSA-2048 sign, which the server does | 2,462 |
| RSA-2048 verify, which the client does | 41,088 |
| X25519 agreement, which both sides do on every handshake | 20,418 |

With ECDSA the server's signature is cheap next to the rest of a connection, so
the handshake rate is set by the event loop, the syscalls and the two TCP
connections rather than by the private key operation, and the three subjects
have room to differ. With RSA-2048 the server's private key operation costs
about seventeen times its verify and bounds the test near 2,460 handshakes per
second per core, and since all three subjects call the same OpenSSL, the RSA
graph should show them close together. That prediction is recorded here before
the run so that the graph can contradict it.

## The tuning journey

Per-subject tuning is a control, so what was changed and why is part of the
method rather than a footnote. Everything here was found by running the thing,
and the order matters because several of these were mistaken for results before
they were understood.

### All three: the runtime

They began on the images each project publishes, which meant nginx on Alpine
with musl and OpenSSL 3.5.5, haproxy on Alpine with 3.5.7, and tlsproxy built
on `alpine:edge`. That is three different libcs-and-crypto combinations, and it
turned out to matter more than anything else measured here:

| | on musl | on glibc | change |
| --- | --- | --- | --- |
| haproxy | ~2,400 hs/s | ~10,900 hs/s | **4.5x** |
| nginx | ~7,400 hs/s | ~8,700 hs/s | 17% |
| tlsproxy | ~7,165 hs/s | ~7,738 hs/s | 8% |

haproxy is the only threaded subject, and musl's allocator serializes where
glibc gives each thread an arena, so haproxy paid for it and the two
process-based subjects barely noticed. Any comparison that had left this
uncontrolled would have been a comparison of allocators. All three now run
Debian 13 with the same glibc and the same libssl3.

### nginx

Started at `worker_connections 65536`, `multi_accept on`, `reuseport`,
`backlog=65535`, session cache and tickets off.

`proxy_timeout 2s` was tried against the upstream connections nginx accumulates
under churn and made no difference at all, so it is not in the config: a setting
that does nothing is worse than no setting, because the next reader assumes it
works. What the accumulation is instead is in "Known defects in the subject".

The systematic sweep of `worker_connections`, `multi_accept`, `accept_mutex`
and `ssl_buffer_size` has **not** been run. nginx is therefore still on
settings chosen by me rather than its own best, and the published comparison
should not go out until it has been.

### haproxy

Started at `nbthread 4`, `maxconn 1000000`, `tune.ssl.cachesize 0`,
`no-tls-tickets`, `mode tcp`.

`maxconn 1000000` made it refuse to start outright: haproxy needs about two
descriptors per connection and raises `RLIMIT_NOFILE` to suit, so it asked for
2,000,034 against the container's 1,048,576 and exited. 200,000 is what it runs
at now, still an order of magnitude above the largest sweep point.

It sits at 3.88 to 3.90 of its four cores, close to saturated, so it is service
rate rather than an idle event loop that bounds it. The sweep of `nbthread`,
`tune.maxaccept`, `tune.bufsize` and `cpu-map` thread pinning has **not** been
run either.

### tlsproxy

Two faults had to be worked around before it would run at all, both now filed.
A self-signed leaf in `cert-chain` refused to start, which is #68, so the
benchmark generates a small CA and issues the leaf from it. Every worker exits
immediately when the master is PID 1, which is #69, so the compose service sets
`init: true` to put tini there instead. That workaround should come out when
#69 is fixed.

There is nothing else to tune: worker count is the CPU budget and is matched,
and #44 means there are no TLS knobs to sweep.

## Measurements

Four modes, all driven by `bench.sh` onto one CSV schema. The harness emits the
CSV, a committed plotting script renders the images, and CSV, script and images
are all committed together.

1. **Handshake rate,** `-m handshake`. New connections per second with no
   resumption, swept over concurrency and per certificate type. This is the
   defining metric for a TLS terminator and the old benchmark did not measure
   it at all. It is a closed-loop number, so it states capacity under a client
   that waits its turn, which is an upper bound rather than a sustainable rate.
2. **Sustainable rate and degradation,** `-m rate`. The same handshakes driven
   from a fixed Poisson arrival schedule, swept over offered rate. This is what
   says where a subject's knee is, and it is not the same number: measured
   here, closed-loop capacity overstated the rate one subject could hold with a
   sub-100ms p99 by about 40%, because the closed loop stops offering work when
   the subject slows down. Past the knee all three deliver *less* than they did
   below it, which is congestion collapse and only an open model can show it.
3. **Memory against held connections,** `-m idle`. N connections established
   and held open, swept over N. Connection churn never has them all live at
   once and so understates per-connection cost badly; the slope of this sweep
   is the honest marginal cost, and its intercept is the fixed footprint. The
   two separate widely between subjects and only this mode separates them.
4. **Data path against payload size,** `-m bulk`. Fixed concurrency over
   persistent connections against the echo sink, swept over payload, in the
   same-host topology because a gigabit link is far below what the subjects
   can move. `TPX_NET_BUFSIZE` in `inc/proxy.h` is 16384, so the 64KB and 1MB
   points are where a payload spans several queue chunks. Connections persist
   for the whole run rather than churning, since at small payloads a churning
   client measures its own ephemeral port table instead of the proxy.

Two derived quantities normalize the rest and carry the comparison: **CPU per
handshake** and **MB/s per core**. A subject that wins on rate while spending a
third more CPU has not won.

## Validity checks

Each of these is recorded as its own column on every row, and any row carrying
one is excluded from the graphs with the number of exclusions printed rather
than dropped quietly. The row is kept either way, since a run discarded at
capture leaves no evidence that it happened.

**Subject saturation.** The subject's cpuset utilization is sampled through the
run. A peak reported while the subject was not saturated is a floor on the
subject and a ceiling on something else, and gets labelled that way.

**Generator headroom.** Before each measured run the generator is pointed at a
sink that costs nothing to serve, and has to produce at least twice the rate
the subject absorbed. A generator that cannot is the ceiling, and a number
taken against one is a measurement of the load generator.

**Thermal state.** The subject is a laptop, so its clocks are the least
repeatable thing in the arrangement. `intel_pstate` is pinned to the
`performance` governor with `no_turbo` set, which holds the base frequency and
gives up peak throughput for runs that can be compared to each other. On top of
that, `thermal_throttle/package_throttle_count` is read before and after every
run and any movement fails it, because a run that throttled part way through
reports a median that no configuration produced.

**Ephemeral ports.** The client closes first in every churn test, so TIME_WAIT
accumulates on the generator. Linux holds TIME_WAIT for 60 seconds and exposes
no sysctl for the length, and the default `ip_local_port_range` of 32768 to
60999 is 28,232 ports, so one source address against one destination socket
sustains 470 new connections per second before running out. The port range, the
`tcp_tw_reuse` setting and the number of source addresses in use are recorded
per run, since a benchmark that plateaus around 470 has measured the
generator's port table.

**Worker deaths.** The subject's worker PIDs are captured before and after each
run and any change fails it. Issue #57 faults a worker in a Release build when
a client closes while the backend connect is still outstanding, which is
ordinary under load, and the master respawning it would otherwise leave a run
that lost connections looking like a run that did not.

**Link speed.** The negotiated speed of the interface in use is read for every
cross-host run. WiFi is not used for any of them, since its jitter and
retransmits would land in the latency percentiles.

## Defects that bear on the numbers

Open against tlsproxy, each landing somewhere specific:

- **#69**, every worker exiting at once when the master is PID 1, which is what
  `CMD ["tlsproxy"]` produces. The compose service sets `init: true` so tini
  holds PID 1 instead. That is a workaround and should come out when #69 does.
- **#68**, `SSL_CTX_build_cert_chain()` returning 2 for a lone self-signed leaf
  and `init_openssl()` treating anything but 1 as fatal. `certs/mkcerts.sh`
  issues the leaf from a small CA to avoid it, which is more representative of a
  real deployment anyway.
- **#45**, no `RLIMIT_NOFILE` raise, no `EMFILE` handling and no
  `max-connections`, which is what the concurrency sweep runs towards.
- **#44**, no group, ciphersuite or version configuration, which is why the TLS
  parameters are pinned at the client rather than at the server.

Closed since the first sweeps and present in the measured tree: **#53**, a
worker spinning on a core after a client disconnect, and **#57**, a double
rbtree insert that faulted the worker under Release. Both were the steady state
of a churn test, so any number taken before they landed is not comparable with
the baseline.

Found in a comparator rather than in tlsproxy, and recorded because it shapes
one of the graphs: **nginx's stream module retains upstream connections** when a
client completes a handshake and disconnects without sending anything. Measured
against the sink, which never times out, nginx accumulates 30,000 to 39,000
upstream sockets against 1,024 live clients and keeps opening more after the
client load stops, and its memory grows with connections *completed* at about
73 KB each rather than with connections held. It is not TLS, since the same
config with no upstream is flat at 190 MB for identical throughput; not the
backend, since it survives a backend with no timeouts; and not the allocator,
since it survives the move from musl to glibc. It stalled nginx outright four
times across the sweeps. The workload that provokes it, high churn through
`stream` from clients that send nothing, is plausible in production as health
checks or scanners but not at thousands per second, so nginx's handshake rate
should be published with its memory beside it rather than alone.

## Provenance

Recorded into every result file, and MISSING until there is a run to record.

| Field | Subject host | Generator host |
| --- | --- | --- |
| Role | MISSING | MISSING |
| OS and version | MISSING | MISSING |
| Live image and its build date | not applicable | MISSING |
| Kernel | MISSING | MISSING |
| CPU model | MISSING | MISSING |
| Cores and threads | MISSING | MISSING |
| RAM | MISSING | MISSING |
| CPU governor and turbo state | MISSING | MISSING |
| NIC | MISSING | MISSING |
| Negotiated link speed | MISSING | MISSING |
| `ip_local_port_range` | MISSING | MISSING |
| `tcp_tw_reuse` | MISSING | MISSING |
| `somaxconn` | MISSING | MISSING |
| `nofile` soft and hard | MISSING | MISSING |
| Docker version | MISSING | MISSING |
| Container runtime | MISSING | MISSING |

| Field | Value |
| --- | --- |
| tlsproxy git SHA | MISSING |
| tlsproxy build type | MISSING |
| OpenSSL version, all three subjects | MISSING |
| nginx version | MISSING |
| haproxy version | MISSING |
| `tlsload` git SHA and build flags | MISSING |
| `tls-perf` commit and build flags | MISSING |
| `wrk2` commit and build flags | MISSING |
| Backend image and version | MISSING |
| Date of run | MISSING |

## Running it

The subject host needs a native Docker; the generator host boots a live image
and keeps nothing across a reboot, so after one it needs the whole of this
again.

```sh
# generator host, once per boot: address, sshd, root password
ip addr add 10.99.0.2/24 dev <iface> && ip link set <iface> up
passwd && rc-service sshd start

# subject host
ssh-add                                     # the key is passphrase-protected
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@10.99.0.2
./generators/build.sh
scp generators/build/{tlsload,tls-perf,wrk,PROVENANCE} \
    root@10.99.0.2:/root/build/
scp tune.sh root@10.99.0.2:/root/
ssh -n root@10.99.0.2 'IFACE=<iface> sh /root/tune.sh generator'
doas env IFACE=enp0s31f6 ./tune.sh subject   # also pins the CPU, see below
```

`tune.sh subject` sets the `performance` governor and `no_turbo`, which holds
the laptop at its 2.5 GHz base clock until the next reboot. That is deliberate,
since repeatable runs matter more here than peak ones, and this chassis
otherwise throttles. To undo it without rebooting, write `0` to
`intel_pstate/no_turbo` and `powersave` back to every `scaling_governor`.

Then any of the four modes:

```sh
./bench.sh -m handshake -x "64 256 1024 4096"
./bench.sh -m rate      -x "2000 4000 6000 8000 10000" -R 4
./bench.sh -m idle      -x "1000 5000 20000" -d 30 -R 3
GEN=local ./bench.sh -m bulk -x "64 1024 8192 65536 1048576" \
    -c 32 -n 0 -d 8 -R 3
```

`bulk` runs with `GEN=local` because a gigabit link caps the data path far
below what the subjects can move, so across the wire it would measure the NIC.
It pins the generator to `6,7,14,15`, off the subject's cpuset. The subject
takes `0-3,8-11`, four whole physical cores with their siblings, and the
backend `4,5,12,13`.

To compare a later run against the reference numbers:

```sh
python3 report.py --against baseline/ results/<newrun>/
```

Percentages are relative to the baseline with positive meaning better, so a
change that makes tlsproxy faster or leaner shows as a positive number whether
the underlying column goes up or down.

## Contents

| Path | State |
| --- | --- |
| `README.md` | this file, the method |
| `bench.sh` | the entry point for all four modes, writing provenance and the git SHA into every result |
| `report.py` | renders a results directory as markdown; `--against baseline/` adds deltas |
| `BASELINE.md` | the reference numbers as a report, with the caveats that stop them being a published result |
| `baseline/` | the CSVs and provenance behind it at `6e847f2`, tracked so a later run has something to diff against |
| `results/` | one directory per run, untracked |
| `tune.sh` | host tuning and its recording, for either role |
| `compose.yml` | the stack: two backends, three subjects, two diagnostics, all behind profiles |
| `subjects/` | one directory per subject, plus the Dockerfiles that put tlsproxy and nginx on the same Debian and libssl3 as haproxy |
| `certs/mkcerts.sh` | a CA and a leaf per algorithm; the leaves are gitignored |
| `backend/nginx.conf` | the HTTP backend, for the tests that speak HTTP over the tunnel |
| `backend/sink/` | the discard/echo backend, static on `scratch` so its cgroup accounts for connection state and nothing else |
| `generators/build.sh` | builds `tlsload`, `tls-perf` and `wrk2` for the generator host and records what they are |
| `generators/tlsload/` | the open-model generator: handshake, hold and request modes, client-pinned TLS parameters, latency percentiles |
| `diag/` | per-second memory and socket-state time series for one subject under load |
| `monitoring.yml` | Prometheus, cAdvisor, node-exporter and Grafana, split out so bringing up the benchmark does not bring them up beside the subject |
| `prometheus.yml` | configuration for the above |
| `plot.py` | planned, matplotlib, CSV in and images out |
| `nginx/` | **superseded and worth deleting.** The pre-rewrite Test B configuration, referenced by nothing, and it carries a committed `ssl/tls.key` |
