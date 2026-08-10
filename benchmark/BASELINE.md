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
| tlsproxy | `6e847f2`, Release, built on Debian 13 by `subjects/tlsproxy/Dockerfile` |
| nginx | 1.29.4, Debian 13, `subjects/nginx/Dockerfile` |
| haproxy | 3.2.22, Debian 13 |
| OpenSSL | libssl3 3.5.6-1~deb13u2 in all three |
| certificate | ECDSA P-256, leaf issued from a per-algorithm CA |
| TLS | 1.3, X25519, `TLS_AES_256_GCM_SHA384`, no resumption, no ALPN |
| workers | 4 per subject, cpuset `0-3,8-11`, four physical cores with siblings |
| backend | `backend-sink`, which never times out |
| subject host | i7-11850H pinned to its 2.5 GHz base clock, `performance`, `no_turbo` |
| generator | separate host over gigabit Ethernet, except `bulk` which is same-host |
| generator tool | `tlsload`, cross-checked against `tls-perf` to within 1.8% |

Full provenance for both hosts, including every sysctl and both generators'
build flags, is in `provenance-handshake.txt` and `provenance-bulk.txt`.

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

Rows failing any validity check, non-zero errors, a worker set that changed, a
cgroup that hit its memory ceiling, a package that throttled, or a generator
that produced no result, are excluded and the count of exclusions is printed.
The first repetition of each point is dropped as the only cold one.

## An unresolved discrepancy on haproxy

**haproxy's handshake number is not trustworthy yet and should not be quoted.**
Two independent generators disagree about it by 44%, while agreeing on the
other two subjects to within 2%:

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

tlsproxy SHA: 6e847f2

## Handshake capacity, closed loop

| subject | concurrency | hs/s | cores | peak MB |
| --- | --- | --- | --- | --- |
| tlsproxy | 64 | 7503 | 3.66 | 25 |
| tlsproxy | 256 | 7547 | 3.68 | 33 |
| tlsproxy | 1024 | 7574 | 3.72 | 53 |
| tlsproxy | 4096 | 7542 | 3.82 | 168 |
| nginx-stream | 64 | 8458 | 3.68 | 393 |
| nginx-stream | 256 | 8517 | 3.76 | 805 |
| nginx-stream | 1024 | 8726 | 3.91 | 1567 |
| nginx-stream | 4096 | 8002 | 4.15 | 3088 |
| haproxy-tcp | 64 | 7503 | 3.71 | 61 |
| haproxy-tcp | 256 | 7469 | 3.70 | 77 |
| haproxy-tcp | 1024 | 7558 | 3.73 | 142 |
| haproxy-tcp | 4096 | 7682 | 3.89 | 410 |

5 row(s) excluded by a validity check.

| subject | concurrency | CPU per handshake |
| --- | --- | --- |
| tlsproxy | 64 | 488 us |
| tlsproxy | 256 | 488 us |
| tlsproxy | 1024 | 492 us |
| tlsproxy | 4096 | 506 us |
| nginx-stream | 64 | 435 us |
| nginx-stream | 256 | 442 us |
| nginx-stream | 1024 | 449 us |
| nginx-stream | 4096 | 519 us |
| haproxy-tcp | 64 | 494 us |
| haproxy-tcp | 256 | 495 us |
| haproxy-tcp | 1024 | 494 us |
| haproxy-tcp | 4096 | 507 us |


## Sustainable rate, open loop

| subject | offered rate | achieved/s | p99 ms | peak MB |
| --- | --- | --- | --- | --- |
| tlsproxy | 2000 | 1995 | 2.1 | 15 |
| tlsproxy | 4000 | 3973 | 4.3 | 18 |
| tlsproxy | 6000 | 5977 | 40.6 | 31 |
| tlsproxy | 8000 | 7625 | 560.6 | 41 |
| tlsproxy | 10000 | 6877 | 4147.7 | 94 |
| nginx-stream | 2000 | 1995 | 1.9 | 126 |
| nginx-stream | 4000 | 3973 | 2.5 | 130 |
| nginx-stream | 6000 | 5978 | 4.8 | 137 |
| nginx-stream | 8000 | 7964 | 8.3 | 146 |
| nginx-stream | 10000 | 8192 | 2466.5 | 3327 |
| haproxy-tcp | 2000 | 1995 | 1.7 | 48 |
| haproxy-tcp | 4000 | 3973 | 2.1 | 50 |
| haproxy-tcp | 6000 | 5978 | 3.2 | 105 |
| haproxy-tcp | 8000 | 7640 | 406.4 | 348 |

5 row(s) excluded by a validity check.


## Memory against held connections

| subject | connections held | peak MB | anon MB |
| --- | --- | --- | --- |
| tlsproxy | 1000 | 86 | 74 |
| tlsproxy | 5000 | 417 | 372 |
| tlsproxy | 20000 | 1459 | 1295 |
| nginx-stream | 1000 | 184 | 172 |
| nginx-stream | 5000 | 430 | 385 |
| nginx-stream | 20000 | 1355 | 1192 |
| haproxy-tcp | 1000 | 99 | 87 |
| haproxy-tcp | 5000 | 334 | 288 |
| haproxy-tcp | 20000 | 1175 | 1012 |


## Data path against payload size

| subject | payload bytes | MB/s | cores |
| --- | --- | --- | --- |
| tlsproxy | 64 | 17 | 2.58 |
| tlsproxy | 1024 | 149 | 2.38 |
| tlsproxy | 8192 | 790 | 2.70 |
| tlsproxy | 65536 | 1715 | 3.09 |
| tlsproxy | 1048576 | 1768 | 3.19 |
| nginx-stream | 64 | 10 | 2.26 |
| nginx-stream | 1024 | 154 | 2.38 |
| nginx-stream | 8192 | 833 | 2.63 |
| nginx-stream | 65536 | 1809 | 2.93 |
| nginx-stream | 1048576 | 1972 | 2.95 |
| haproxy-tcp | 64 | 9 | 2.58 |
| haproxy-tcp | 1024 | 139 | 2.66 |
| haproxy-tcp | 8192 | 787 | 2.77 |
| haproxy-tcp | 65536 | 1520 | 2.88 |
| haproxy-tcp | 1048576 | 1560 | 2.81 |

