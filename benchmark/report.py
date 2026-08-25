#!/usr/bin/env python3
"""Render benchmark CSVs as a markdown report, optionally against a baseline.

    report.py baseline/                       the baseline as it stands
    report.py --against baseline/ results/*/  a new sweep with deltas

Reps are medians over everything but the first, which follows a container start
and is the only cold one. Rows failing a validity check are excluded and the
count of exclusions is printed rather than dropped quietly.
"""
import csv
import os
import statistics as st
import sys

SUBJECTS = ["tlsproxy", "hitch", "nginx-stream", "haproxy-tcp"]


def load(path):
    """Return {mode: [row, ...]} for every CSV under path."""
    out = {}
    for root, _, files in os.walk(path):
        for f in files:
            if not f.endswith(".csv"):
                continue
            rows = list(csv.DictReader(open(os.path.join(root, f))))
            if not rows:
                continue
            mode = rows[0].get("mode") or "handshake"
            out.setdefault(mode, []).extend(rows)
    return out


# Errors were once judged against zero, which stopped working the moment the
# generator got its full sixteen threads: haproxy then failed 2 to 5 connections
# in every 100,000, which is 0.005% and is not a broken run, and the absolute
# rule threw away every haproxy row in the sweep for it. A rate keeps those and
# still excludes nginx at 4096 concurrency, which fails 0.19%.
ERROR_RATE_LIMIT = 0.0001


def too_many_errors(r):
    errors = int(r.get("errors", 0) or 0)
    if errors == 0:
        return False
    completed = int(r.get("completed", 0) or 0)
    return completed == 0 or errors / completed > ERROR_RATE_LIMIT


def valid(rows):
    """Drop rows that failed a validity check, and say how many."""
    keep, drop = [], 0
    for r in rows:
        if int(r.get("rep", 1)) <= 1:
            continue
        bad = (r.get("run_ok", "1") != "1"
               or too_many_errors(r)
               or int(r.get("mem_max_delta", 0)) != 0
               or int(r.get("throttle_delta", 0)) != 0
               or r.get("workers_stable", "1") != "1")
        if bad:
            drop += 1
        else:
            keep.append(r)
    return keep, drop


def generator_bound(rows, limit=70.0):
    """Rows where the generator was busier than it should have been.

    A subject that is not saturated while the generator is means the number
    describes the generator. This does not exclude the row, because a busy
    generator is not automatically a wrong measurement, only a suspect one.
    """
    n = 0
    for r in rows:
        try:
            if float(r.get("gen_busy_pct") or 0) >= limit:
                n += 1
        except ValueError:
            pass
    return n


# The first handshake sweeps were driven by tls-perf and called this column
# hs_avg; bench.sh calls it rate. Tolerate both so an old CSV still renders.
ALIAS = {"rate": ("rate", "hs_avg")}


def med(rows, key, scale=1.0):
    v = []
    for r in rows:
        for k in ALIAS.get(key, (key,)):
            if r.get(k) not in (None, ""):
                v.append(float(r[k]) * scale)
                break
    return st.median(v) if v else 0.0


def iqr(rows, key):
    v = sorted(float(r[key]) for r in rows if r.get(key) not in (None, ""))
    if len(v) < 4:
        return 0.0
    q = st.quantiles(v, n=4)
    return q[2] - q[0]


def axis_of(rows):
    return sorted({r.get("axis") or r.get("concurrency") for r in rows},
                  key=lambda x: int(x))


def cell(v, base, fmt="{:.0f}", lower_is_better=False):
    if base is None or base == 0:
        return fmt.format(v)
    d = (v - base) / base * 100.0
    if lower_is_better:
        d = -d
    if d == 0.0:
        d = 0.0                     # else negating zero prints as "+-0%"
    sign = "+" if d >= 0 else ""
    return f"{fmt.format(v)} ({sign}{d:.0f}%)"


SPEC = {
    "handshake": ("Handshake capacity, closed loop", "concurrency",
                  [("rate", "hs/s", 1.0, "{:.0f}", False),
                   ("cpu_cores", "cores", 1.0, "{:.2f}", True),
                   ("ws_peak_bytes", "peak MB", 1 / 1048576, "{:.0f}", True)]),
    "rate":      ("Sustainable rate, open loop", "offered rate",
                  [("rate", "achieved/s", 1.0, "{:.0f}", False),
                   ("hs_p99", "p99 ms", 1.0, "{:.1f}", True),
                   ("ws_peak_bytes", "peak MB", 1 / 1048576, "{:.0f}", True)]),
    "idle":      ("Memory against held connections", "connections held",
                  [("ws_peak_bytes", "peak MB", 1 / 1048576, "{:.0f}", True),
                   ("anon_bytes", "anon MB", 1 / 1048576, "{:.0f}", True)]),
    "bulk":      ("Data path against payload size", "payload bytes",
                  [("mb_per_sec", "MB/s", 1.0, "{:.0f}", False),
                   ("cpu_cores", "cores", 1.0, "{:.2f}", True)]),
    # A message mode row describes a round trip on a connection that was
    # already up, so the interesting columns are the tail and the missed slots,
    # not the median, which every subject gets right.
    "message":   ("Message round trip on held connections", "connections",
                  [("msg_p50", "p50 ms", 1.0, "{:.2f}", True),
                   ("msg_p99", "p99 ms", 1.0, "{:.2f}", True),
                   ("msg_p999", "p999 ms", 1.0, "{:.2f}", True),
                   ("msg_max", "max ms", 1.0, "{:.1f}", True),
                   ("rate", "msg/s", 1.0, "{:.0f}", False),
                   ("shed", "missed slots", 1.0, "{:.0f}", True)]),
}


def render(mode, rows, base_rows):
    title, axis_name, cols = SPEC.get(
        mode, (mode, "axis", [("rate", "rate", 1.0, "{:.0f}", False)]))
    keep, dropped = valid(rows)
    if not keep:
        return f"\n## {mode}\n\nNo valid rows.\n"
    bkeep, _ = valid(base_rows) if base_rows else ([], 0)

    head = f"| subject | {axis_name} | " + " | ".join(c[1] for c in cols) + " |"
    sep = "| --- " * (len(cols) + 2) + "|"
    out = [f"\n## {title}\n", head, sep]
    for s in SUBJECTS:
        for a in axis_of([r for r in keep if r["subject"] == s]):
            g = [r for r in keep if r["subject"] == s
                 and (r.get("axis") or r.get("concurrency")) == a]
            b = [r for r in bkeep if r["subject"] == s
                 and (r.get("axis") or r.get("concurrency")) == a]
            cells = []
            for key, _, scale, fmt, lower in cols:
                cells.append(cell(med(g, key, scale),
                                  med(b, key, scale) if b else None,
                                  fmt, lower))
            out.append(f"| {s} | {a} | " + " | ".join(cells) + " |")
    if dropped:
        out.append(f"\n{dropped} row(s) excluded by a validity check.")
    busy = generator_bound(keep)
    if busy:
        out.append(f"\n{busy} row(s) had the generator above 70% busy, so they "
                   f"may describe the generator rather than the subject.")
    if mode == "handshake":
        out.append("")
        out.append("| subject | concurrency | CPU per handshake |")
        out.append("| --- | --- | --- |")
        for s in SUBJECTS:
            for a in axis_of([r for r in keep if r["subject"] == s]):
                g = [r for r in keep if r["subject"] == s
                     and (r.get("axis") or r.get("concurrency")) == a]
                r_, c_ = med(g, "rate"), med(g, "cpu_cores")
                if r_:
                    out.append(f"| {s} | {a} | {c_ / r_ * 1e6:.0f} us |")
    return "\n".join(out) + "\n"


def main():
    args = sys.argv[1:]
    base = None
    if args and args[0] == "--against":
        base = load(args[1])
        args = args[2:]
    if not args:
        print(__doc__)
        return 2
    data = {}
    for p in args:
        for m, rows in load(p).items():
            data.setdefault(m, []).extend(rows)
    shas = sorted({r.get("sha", "?") for rows in data.values() for r in rows})
    print(f"tlsproxy SHA: {', '.join(shas)}")
    if base:
        print("Percentages are against the baseline, positive meaning better.")
    for m in ["handshake", "rate", "idle", "bulk", "message"]:
        if m in data:
            print(render(m, data[m], base.get(m) if base else None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
