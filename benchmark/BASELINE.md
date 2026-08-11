# Baseline numbers

Reference measurements for before-and-after comparison of tlsproxy. **This is
not a published result.** The per-subject tuning sweeps in
`README.md#the-tuning-journey` have not been run, so nginx and haproxy are on
settings I chose rather than their own best, and only the ECDSA certificate has
been measured. Nothing here should go into the project README until both are
done.

Regenerate this table from the committed CSVs:

```sh
python3 report.py baseline/
```

Compare a later sweep against it:

```sh
./bench.sh -m handshake -x "64 256 1024 4096"
python3 report.py --against baseline/ results/<newrun>/
```

Percentages are relative to the baseline with **positive meaning better**, so a
change that makes tlsproxy faster or leaner reads as positive whichever
direction the underlying column moves.

## What produced these

| | |
| --- | --- |
| tlsproxy | `8e2dbee`, Release, built on Debian 13 by `subjects/tlsproxy/Dockerfile` |
| nginx | 1.29.4, Debian 13, `subjects/nginx/Dockerfile` |
| haproxy | 3.2.22, Debian 13 |
| OpenSSL | libssl3 3.5.6-1~deb13u2 in all three |
| certificate | ECDSA P-256, leaf issued from a per-algorithm CA |
| TLS | 1.3, X25519, `TLS_AES_256_GCM_SHA384`, no resumption, no ALPN |
| workers | 8 per subject, cpuset `0-3,8-11`, four physical cores with their siblings, so one worker per logical CPU |
| backend | `backend-sink`, which never times out |
| subject host | i7-11850H pinned to its 2.5 GHz base clock, `performance`, `no_turbo` |
| generator | separate host over gigabit Ethernet, except `bulk` which is same-host |
| generator tool | `tlsload`, cross-checked against `tls-perf` to within 1.8% |

Full provenance for both hosts, including every sysctl and both generators'
build flags, is in `provenance-<mode>.txt`, one per mode.

**Taken on 2026-08-11 at `8e2dbee`, replacing the `6e847f2` set and the
short-lived `9b38c8f` one.** Several things changed between them and each moves
the numbers on its own, so none of these is a like for like comparison with
anything measured earlier: every subject went from four workers to eight, one
per logical CPU in the cpuset rather than half of them; #92 added
`SSL_MODE_RELEASE_BUFFERS`, which is most of the idle table; #93 set
`TCP_NODELAY` on both legs and #94 removed six syscalls per connection; and the
generator went from four threads to one per CPU it owns.

That last one is not a detail. At four threads the generator could not service
20,000 held connections fast enough to time them, and reported a p99 of 158 ms
against a subject using one of its eight cores. The same point with the
generator properly sized reads 2.66 ms. Any message number taken before
2026-08-11 describes the generator.

## How to read each mode

**Handshake** is closed-loop capacity: the client holds a fixed number of
connections and starts a new one only as an old one finishes. It is an upper
bound rather than a sustainable rate.

**Rate** is the same work from a fixed Poisson arrival schedule, which is what
says where the knee is. All three suffer congestion collapse above it,
delivering less than they did below.

**Idle** holds connections open. Its slope is the marginal cost of a held
connection and its intercept is the fixed footprint; the two rank the subjects
differently and only this mode separates them.

**Bulk** is the data path over persistent connections against an echo sink,
same-host because a gigabit link is far below what the subjects can move.

**Message** holds connections open and sends one 200 byte message per
connection per second, measuring the round trip rather than the handshake. It is
the steady state of the workloads this proxy is for, and none of the other four
modes can see it: handshake and rate close a connection as soon as it is up,
idle sends nothing, and bulk streams continuously. The 33 ms lockstep tick
variant, which is the shape a game server has, is not in this directory because
`report.py` merges every CSV by mode and two message sweeps at different
intervals would average into one table; its run is
`results/20260811T065752Z`.

Rows failing any validity check, too many errors, a worker set that changed, a
cgroup that hit its memory ceiling, a package that throttled, or a generator
that produced no result, are excluded and the count of exclusions is printed.
The first repetition of each point is dropped as the only cold one.

"Too many errors" is a rate rather than zero, currently one failed connection in
10,000. It was zero until 2026-08-11, when the generator was given its full
sixteen threads and haproxy began failing 2 to 5 connections in every 100,000 at
every concurrency, which is 0.005% and not a broken run; an absolute rule threw
away every haproxy row in the sweep for it. The rate still excludes nginx at
4096 concurrency, which fails 0.19% of connections. tlsproxy has not yet failed
one, at any concurrency, in any sweep.

## An unresolved discrepancy on haproxy

**haproxy's handshake number is not trustworthy yet and should not be quoted.**
Two independent generators disagree about it by 44%, while agreeing on the
other two subjects to within 2%. The cross-check below is from the `6e847f2` set
at four workers and has not been repeated against the current one, so treat the
absolute figures in this section as historical and the question as still open:

| subject | tlsload | tls-perf | gap |
| --- | --- | --- | --- |
| tlsproxy | 7,574 | 7,738 | 2% |
| nginx-stream | 8,726 | 8,738 | 0.1% |
| haproxy-tcp | 7,558 | 10,881 | **44%** |

Both are internally consistent: Little's law on each gives about 1,024 in
flight against a configured 1,024, so both really are running the concurrency
they claim. The difference is per-connection cost. haproxy spends 494 us of CPU
per handshake under tlsload against 364 us under tls-perf, at 3.70 cores
against 3.91, so it is doing more work rather than sitting idle.

Ruled out: it is not the teardown. Adding `close_notify` before closing, which
is `tlsload -S`, moves it by less than 1%.

The untested hypothesis is arrival burstiness. tlsload refills every completed
slot in one pass of its loop, so connections arrive in bursts, and haproxy is
the only subject whose workers are threads sharing state rather than processes
partitioned by `SO_REUSEPORT`, which is where burst-driven contention would
show. Until that is confirmed or refuted, the handshake table below records
tlsload's figure and this section records tls-perf's, and neither is published.

The other three modes are unaffected: `idle` and `bulk` do not churn
connections, and `rate` drives arrivals from a fixed Poisson schedule rather
than from completions, which is exactly the property in question.


## Handshake capacity, closed loop

| subject | concurrency | hs/s | cores | peak MB |
| --- | --- | --- | --- | --- |
| tlsproxy | 64 | 10329 | 7.34 | 31 |
| tlsproxy | 256 | 10299 | 7.34 | 43 |
| tlsproxy | 1024 | 10313 | 7.43 | 70 |
| tlsproxy | 4096 | 10261 | 7.59 | 131 |
| nginx-stream | 64 | 10574 | 7.44 | 1002 |
| nginx-stream | 256 | 10573 | 7.59 | 1520 |
| nginx-stream | 1024 | 10154 | 7.80 | 2725 |
| haproxy-tcp | 64 | 9835 | 7.43 | 80 |
| haproxy-tcp | 256 | 9686 | 7.43 | 97 |
| haproxy-tcp | 1024 | 9481 | 7.48 | 161 |
| haproxy-tcp | 4096 | 9387 | 7.72 | 422 |

5 row(s) excluded by a validity check.

| subject | concurrency | CPU per handshake |
| --- | --- | --- |
| tlsproxy | 64 | 711 us |
| tlsproxy | 256 | 713 us |
| tlsproxy | 1024 | 720 us |
| tlsproxy | 4096 | 739 us |
| nginx-stream | 64 | 704 us |
| nginx-stream | 256 | 718 us |
| nginx-stream | 1024 | 769 us |
| haproxy-tcp | 64 | 756 us |
| haproxy-tcp | 256 | 767 us |
| haproxy-tcp | 1024 | 789 us |
| haproxy-tcp | 4096 | 822 us |


## Sustainable rate, open loop

| subject | offered rate | achieved/s | p99 ms | peak MB |
| --- | --- | --- | --- | --- |
| tlsproxy | 2000 | 2009 | 1.7 | 17 |
| tlsproxy | 4000 | 4026 | 2.1 | 20 |
| tlsproxy | 6000 | 6012 | 3.0 | 20 |
| tlsproxy | 8000 | 7997 | 5.7 | 21 |
| tlsproxy | 10000 | 9977 | 54.5 | 42 |
| nginx-stream | 2000 | 2009 | 1.6 | 239 |
| nginx-stream | 4000 | 4026 | 1.8 | 242 |
| nginx-stream | 6000 | 6012 | 2.3 | 244 |
| nginx-stream | 8000 | 7997 | 3.4 | 249 |
| nginx-stream | 10000 | 9982 | 11.8 | 288 |
| haproxy-tcp | 2000 | 2009 | 1.4 | 50 |
| haproxy-tcp | 4000 | 4026 | 1.6 | 53 |
| haproxy-tcp | 6000 | 6012 | 1.9 | 89 |
| haproxy-tcp | 8000 | 7997 | 2.5 | 89 |
| haproxy-tcp | 10000 | 9889 | 93.9 | 168 |


## Memory against held connections

| subject | connections held | peak MB | anon MB |
| --- | --- | --- | --- |
| tlsproxy | 1000 | 78 | 64 |
| tlsproxy | 5000 | 315 | 269 |
| tlsproxy | 20000 | 906 | 741 |
| nginx-stream | 1000 | 307 | 292 |
| nginx-stream | 5000 | 552 | 505 |
| nginx-stream | 20000 | 1443 | 1277 |
| haproxy-tcp | 1000 | 113 | 99 |
| haproxy-tcp | 5000 | 345 | 298 |
| haproxy-tcp | 20000 | 1112 | 947 |


## Data path against payload size

| subject | payload bytes | MB/s | cores |
| --- | --- | --- | --- |
| tlsproxy | 64 | 19 | 3.23 |
| tlsproxy | 1024 | 159 | 2.89 |
| tlsproxy | 8192 | 940 | 3.47 |
| tlsproxy | 65536 | 2221 | 4.60 |
| tlsproxy | 1048576 | 2148 | 5.57 |
| nginx-stream | 64 | 10 | 2.73 |
| nginx-stream | 1024 | 159 | 2.85 |
| nginx-stream | 8192 | 936 | 3.40 |
| nginx-stream | 65536 | 2162 | 4.53 |
| nginx-stream | 1048576 | 2340 | 4.84 |
| haproxy-tcp | 64 | 10 | 3.35 |
| haproxy-tcp | 1024 | 150 | 3.42 |
| haproxy-tcp | 8192 | 893 | 3.74 |
| haproxy-tcp | 65536 | 1791 | 4.47 |
| haproxy-tcp | 1048576 | 1821 | 4.49 |


## Message round trip on held connections

| subject | connections | p50 ms | p99 ms | p999 ms | max ms | msg/s | missed slots |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tlsproxy | 1000 | 0.39 | 0.79 | 6.54 | 33.2 | 992 | 7 |
| tlsproxy | 5000 | 0.27 | 1.58 | 150.54 | 185.8 | 4925 | 4 |
| tlsproxy | 20000 | 0.25 | 2.66 | 286.79 | 447.9 | 19225 | 2 |
| nginx-stream | 1000 | 0.39 | 0.78 | 49.28 | 78.9 | 992 | 6 |
| nginx-stream | 5000 | 0.28 | 30.41 | 310.59 | 348.7 | 4929 | 2 |
| nginx-stream | 20000 | 0.25 | 830.67 | 1539.30 | 1742.6 | 19200 | 4656 |
| haproxy-tcp | 1000 | 0.45 | 0.88 | 29.98 | 56.9 | 992 | 7 |
| haproxy-tcp | 5000 | 0.29 | 0.62 | 202.41 | 252.6 | 4923 | 4 |
| haproxy-tcp | 20000 | 0.25 | 657.33 | 952.60 | 1133.9 | 19272 | 320 |

tlsproxy SHA: 8e2dbee
