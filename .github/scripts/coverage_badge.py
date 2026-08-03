#!/usr/bin/env python3
"""Render a coverage badge SVG from a gcovr --json-summary file.

Kept in the repo rather than pulled from an action so the badge cannot change
shape under us, and so the number on it always comes from the same gcovr run
that enforced the floor. Usage:

    gcovr ... --json-summary coverage.json
    python3 .github/scripts/coverage_badge.py coverage.json coverage.svg
"""
import json
import os
import sys

# shields.io's palette, so the badge sits next to the others without clashing.
THRESHOLDS = [
    (95, "#4c1"),      # brightgreen
    (90, "#97ca00"),   # green
    (75, "#a4a61d"),   # yellowgreen
    (60, "#dfb317"),   # yellow
    (40, "#fe7d37"),   # orange
    (0,  "#e05d44"),   # red
]

TEMPLATE = """<svg xmlns="http://www.w3.org/2000/svg" \
xmlns:xlink="http://www.w3.org/1999/xlink" width="{total}" height="20" \
role="img" aria-label="coverage: {pct}%">
  <title>coverage: {pct}%</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_w}" height="20" fill="#555"/>
    <rect x="{label_w}" width="{value_w}" height="20" fill="{colour}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" \
font-family="Verdana,Geneva,DejaVu Sans,sans-serif" \
text-rendering="geometricPrecision" font-size="110">
    <text x="{label_x}" y="150" fill="#010101" fill-opacity=".3" \
transform="scale(.1)" textLength="{label_t}">coverage</text>
    <text x="{label_x}" y="140" transform="scale(.1)" \
textLength="{label_t}">coverage</text>
    <text x="{value_x}" y="150" fill="#010101" fill-opacity=".3" \
transform="scale(.1)" textLength="{value_t}">{pct}%</text>
    <text x="{value_x}" y="140" transform="scale(.1)" \
textLength="{value_t}">{pct}%</text>
  </g>
</svg>
"""


def colour_for(pct):
    for floor, colour in THRESHOLDS:
        if pct >= floor:
            return colour
    return THRESHOLDS[-1][1]


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: coverage_badge.py <gcovr-json-summary> <out.svg>")

    in_path = sys.argv[1]
    out_path = sys.argv[2]

    if not os.path.exists(in_path):
        sys.exit(f"input file not found: {in_path}")

    with open(in_path) as fh:
        summary = json.load(fh)

    # gcovr writes line_percent as a float; round the way the floor check does.
    pct = int(round(summary["line_percent"]))

    # 7px per character at font-size 11 is what shields.io uses, plus padding.
    label_w = 62
    value_w = 7 * len(f"{pct}%") + 10
    total = label_w + value_w

    svg = TEMPLATE.format(
        total=total,
        label_w=label_w,
        value_w=value_w,
        colour=colour_for(pct),
        pct=pct,
        label_x=label_w * 5,
        label_t=(label_w - 10) * 10,
        value_x=(label_w + value_w / 2) * 10,
        value_t=(value_w - 10) * 10,
    )

    # ensure output directory exists
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "w") as fh:
        fh.write(svg)

    print(f"coverage {pct}% -> {out_path}")    


if __name__ == "__main__":
    main()
