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
| tlsproxy | `9b38c8f`, Release, built on Debian 13 by `subjects/tlsproxy/Dockerfile` |
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

**Taken on 2026-08-11, replacing the `6e847f2` set.** Three things changed
between them and each moves the numbers on its own, so this is not a like for
like comparison with anything measured earlier: every subject went from four
workers to eight, which is one per logical CPU in the cpuset rather than half of
them; #92 added `SSL_MODE_RELEASE_BUFFERS`, which is most of the change in the
idle table; and #93 set `TCP_NODELAY` on both legs, which is the message table.
The `6e847f2` numbers are in git history if a specific one is wanted.

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

Rows failing any validity check, non-zero errors, a worker set that changed, a
cgroup that hit its memory ceiling, a package that throttled, or a generator
that produced no result, are excluded and the count of exclusions is printed.
The first repetition of each point is dropped as the only cold one.

Two rows were excluded from this set, both haproxy at 4096 concurrency, with one
and three errors out of about 92,000 connections each. Nothing else in the six
sweeps failed a check.

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
| tlsproxy | 64 | 9587 | 7.15 | 27 |
| tlsproxy | 256 | 9701 | 7.30 | 34 |
| tlsproxy | 1024 | 9742 | 7.40 | 73 |
| tlsproxy | 4096 | 9672 | 7.56 | 172 |
| nginx-stream | 64 | 10659 | 7.29 | 401 |
| nginx-stream | 256 | 10335 | 7.39 | 631 |
| nginx-stream | 1024 | 9974 | 7.67 | 1455 |
| nginx-stream | 4096 | 9845 | 8.20 | 2970 |
| haproxy-tcp | 64 | 9979 | 7.42 | 64 |
| haproxy-tcp | 256 | 9734 | 7.42 | 85 |
| haproxy-tcp | 1024 | 9457 | 7.44 | 146 |
| haproxy-tcp | 4096 | 9231 | 7.71 | 407 |

2 row(s) excluded by a validity check.

| subject | concurrency | CPU per handshake |
| --- | --- | --- |
| tlsproxy | 64 | 746 us |
| tlsproxy | 256 | 753 us |
| tlsproxy | 1024 | 759 us |
| tlsproxy | 4096 | 781 us |
| nginx-stream | 64 | 684 us |
| nginx-stream | 256 | 715 us |
| nginx-stream | 1024 | 769 us |
| nginx-stream | 4096 | 833 us |
| haproxy-tcp | 64 | 744 us |
| haproxy-tcp | 256 | 762 us |
| haproxy-tcp | 1024 | 787 us |
| haproxy-tcp | 4096 | 835 us |


## Sustainable rate, open loop

| subject | offered rate | achieved/s | p99 ms | peak MB |
| --- | --- | --- | --- | --- |
| tlsproxy | 2000 | 1995 | 1.8 | 17 |
| tlsproxy | 4000 | 3973 | 2.3 | 19 |
| tlsproxy | 6000 | 5978 | 3.7 | 21 |
| tlsproxy | 8000 | 7965 | 7.9 | 30 |
| tlsproxy | 10000 | 9720 | 410.0 | 49 |
| nginx-stream | 2000 | 1995 | 1.7 | 238 |
| nginx-stream | 4000 | 3973 | 2.2 | 242 |
| nginx-stream | 6000 | 5978 | 2.8 | 244 |
| nginx-stream | 8000 | 7965 | 4.5 | 248 |
| nginx-stream | 10000 | 9986 | 120.9 | 375 |
| haproxy-tcp | 2000 | 1995 | 1.6 | 50 |
| haproxy-tcp | 4000 | 3973 | 2.0 | 53 |
| haproxy-tcp | 6000 | 5978 | 2.6 | 103 |
| haproxy-tcp | 8000 | 7965 | 3.8 | 103 |
| haproxy-tcp | 10000 | 9811 | 171.2 | 238 |


## Memory against held connections

| subject | connections held | peak MB | anon MB |
| --- | --- | --- | --- |
| tlsproxy | 1000 | 83 | 71 |
| tlsproxy | 5000 | 320 | 275 |
| tlsproxy | 20000 | 909 | 745 |
| nginx-stream | 1000 | 296 | 283 |
| nginx-stream | 5000 | 545 | 500 |
| nginx-stream | 20000 | 1453 | 1288 |
| haproxy-tcp | 1000 | 103 | 90 |
| haproxy-tcp | 5000 | 337 | 292 |
| haproxy-tcp | 20000 | 1187 | 1023 |


## Data path against payload size

| subject | payload bytes | MB/s | cores |
| --- | --- | --- | --- |
| tlsproxy | 64 | 19 | 3.21 |
| tlsproxy | 1024 | 159 | 2.88 |
| tlsproxy | 8192 | 941 | 3.45 |
| tlsproxy | 65536 | 2231 | 4.59 |
| tlsproxy | 1048576 | 2171 | 5.58 |
| nginx-stream | 64 | 11 | 2.74 |
| nginx-stream | 1024 | 161 | 2.87 |
| nginx-stream | 8192 | 941 | 3.42 |
| nginx-stream | 65536 | 2189 | 4.56 |
| nginx-stream | 1048576 | 2340 | 4.82 |
| haproxy-tcp | 64 | 10 | 3.35 |
| haproxy-tcp | 1024 | 153 | 3.45 |
| haproxy-tcp | 8192 | 921 | 3.79 |
| haproxy-tcp | 65536 | 1799 | 4.46 |
| haproxy-tcp | 1048576 | 1844 | 4.51 |


## Message round trip on held connections

| subject | connections | p50 ms | p99 ms | p999 ms | max ms | msg/s | missed slots |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tlsproxy | 1000 | 0.41 | 0.84 | 20.27 | 37.9 | 995 | 1 |
| tlsproxy | 5000 | 0.28 | 0.57 | 190.32 | 198.2 | 4920 | 0 |
| tlsproxy | 20000 | 0.29 | 139.45 | 455.85 | 552.2 | 19047 | 0 |
| nginx-stream | 1000 | 0.36 | 0.81 | 33.03 | 65.4 | 996 | 0 |
| nginx-stream | 5000 | 0.29 | 0.60 | 249.50 | 263.2 | 4920 | 0 |
| nginx-stream | 20000 | 0.29 | 623.24 | 1489.63 | 1654.4 | 19019 | 3255 |
| haproxy-tcp | 1000 | 0.35 | 0.74 | 16.72 | 56.7 | 996 | 1 |
| haproxy-tcp | 5000 | 0.30 | 0.61 | 199.47 | 208.1 | 4922 | 0 |
| haproxy-tcp | 20000 | 0.30 | 516.30 | 1011.17 | 1416.6 | 19074 | 1880 |

tlsproxy SHA: 9b38c8f
