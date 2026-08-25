# Lite topology

Subject and generator on one machine, for a comparison that will not be
published. The published method is `../README.md`; this directory holds only
what had to change to fit both halves of the test onto one laptop, and every
difference is a reason the numbers here cannot be compared against
`../baseline/`.

| | published | lite |
| --- | --- | --- |
| generator | second host, wired Ethernet | container on the bench network |
| subject cpuset | `0-3,8-11`, four physical cores | `0,1,8,9`, two |
| generator cpuset | the whole of the other machine | `3-7,11-15`, five physical cores |
| backend cpuset | `4,5,12,13` | `2,10` |
| workers per subject | 8 | 4, one per logical CPU in the cpuset |
| reps | 6, first discarded | 4 or 3, first discarded |
| duration | 10s | 8s, except where a run says otherwise |

## Why the subject gets less of the machine than the generator

With an ECDSA leaf the client does the more expensive half of the handshake,
10,888 P-256 verifies a second per core against the server's 33,851 signatures,
so a subject and a generator with equal budgets produce a generator-bound
number. Measured at four subject cores against three generator cores, tlsproxy
and hitch read 9,634 and 9,882 handshakes a second with the generator 95% busy,
which is a description of the generator rather than of either subject. Those
two figures were taken before `tune.sh subject` pinned the clock, so they are
not comparable with anything else here; what they establish is the shape, not
the value.

At two subject cores against five, every row of the sweep came in with the
generator between 18% and 27% busy. `tlsload` reports its own `getrusage` as
`gen_busy_pct` and `bench.sh` copies it into the CSV column of that name, so
each row carries the evidence for whether it belongs to the subject.

## The machine drifts, and the sweep puts the drift on one subject

`bench.sh` runs a subject's reps consecutively, so anything that changes over
the length of a run lands on whichever subject was late in the order rather
than spreading across all of them. On this laptop that is not hypothetical.
Alternating tlsproxy and hitch at 1,024 concurrent, one rep each, six rounds:

| round | tlsproxy | hitch |
| --- | --- | --- |
| 1 | 4998 | 4691 |
| 2 | 5004 | 4691 |
| 3 | 5014 | 4693 |
| 4 | 4996 | 4174 |
| 5 | 4389 | 4247 |
| 6 | 4386 | 4352 |

Both fall by about 12% over five minutes of sustained load, with the governor
at `performance` and `no_turbo` set, so it is not the clock being allowed to
boost and then stopping. `package_throttle_count` did not move on any rep. The
gap between the two survives every round, which is what makes the handshake
result usable, but a single-subject-at-a-time sweep on this host will read the
last subject low. haproxy, which runs last, dropped from 4,930 handshakes a
second at 256 concurrent to 1,869 at 1,024 in the same sweep, and that number
should be treated as an artefact rather than as haproxy's.

Interleave anything that matters.

## Why a container rather than the published port

A published port on loopback is not DNAT: the `nat OUTPUT` rule docker installs
excludes `127.0.0.0/8`, so `GEN=local` against `127.0.0.1:8443` is relayed by
`docker-proxy` in userland. With one connection open, the host namespace shows
both a `127.0.0.1:33504 ↔ 127.0.0.1:8443` pair and a separate
`172.18.0.1:50208 → 172.18.0.3:8443`, which is the relay's own leg. A container
on the bench network reaches the subject over the bridge with nothing in
between, and it gets its own network namespace, so the generator has a whole
ephemeral port range and its own `tcp_tw_reuse` without the host's being
touched. The host's `tcp_tw_reuse` is 2, which is loopback only, and the bridge
is not loopback.
