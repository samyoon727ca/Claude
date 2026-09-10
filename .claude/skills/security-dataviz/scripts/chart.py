#!/usr/bin/env python3
"""Briefing-grade SVG charts from security-analysis output. No dependencies.

Reads the CSVs the other skills emit (firmware-triage sinks.csv, binary-diff
diff-candidates.csv) or any label,value CSV, and writes a standalone, theme-aware
(light/dark), accessible SVG suitable for a report or slide. For palette/design
rationale, load the `dataviz` skill; this tool applies that method to the fixed
data shapes of a firmware assessment.

Usage:
    chart.py bars --csv sinks.csv --label path --value score --top 10 \
        --title "Top sink candidates" [--color-by severity] --out chart.svg
"""
import argparse
import csv
import html
import sys

# Accessible, theme-stable palette (see the dataviz skill for the canonical set).
ACCENT = "#3B7DD8"
SEV_BANDS = [  # (min_score, label, light, dark)
    (9.0, "Critical", "#B4232A", "#F2555D"),
    (7.0, "High", "#C6641B", "#F08A3C"),
    (4.0, "Medium", "#B8901A", "#E7B93E"),
    (0.1, "Low", "#2E7D46", "#54B072"),
    (0.0, "None", "#6B7280", "#9AA4B2"),
]


def sev_class(v):
    for mn, label, _l, _d in SEV_BANDS:
        if v >= mn:
            return label
    return "None"


def esc(s):
    return html.escape(str(s), quote=True)


def read_rows(path, label_col, value_col, top):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if label_col not in r or value_col not in r:
                sys.exit(f"columns {label_col!r}/{value_col!r} not in CSV headers: {list(r)}")
            try:
                v = float(r[value_col])
            except (ValueError, TypeError):
                continue
            rows.append((r[label_col], v))
    rows.sort(key=lambda t: t[1], reverse=True)
    return rows[:top] if top else rows


def trunc(s, n=42):
    return s if len(s) <= n else "…" + s[-(n - 1):]


def bars_svg(rows, title, color_by):
    W = 780
    pad_l, pad_r, pad_t, pad_b = 300, 70, 56, 24
    row_h, gap = 26, 8
    plot_w = W - pad_l - pad_r
    H = pad_t + pad_b + len(rows) * (row_h + gap)
    vmax = max((v for _, v in rows), default=1) or 1

    css = f"""
    .bg{{fill:var(--bg)}} .title{{fill:var(--fg);font:600 17px system-ui,sans-serif}}
    .lbl{{fill:var(--fg);font:13px ui-monospace,monospace}}
    .val{{fill:var(--muted);font:600 12px system-ui,sans-serif}}
    .bar{{fill:{ACCENT}}} .axis{{stroke:var(--grid);stroke-width:1}}
    :root{{--bg:#ffffff;--fg:#1a1a1a;--muted:#555;--grid:#e2e2e2}}
    .Critical{{fill:{SEV_BANDS[0][2]}}} .High{{fill:{SEV_BANDS[1][2]}}}
    .Medium{{fill:{SEV_BANDS[2][2]}}} .Low{{fill:{SEV_BANDS[3][2]}}} .None{{fill:{SEV_BANDS[4][2]}}}
    @media (prefers-color-scheme:dark){{
      :root{{--bg:#14161a;--fg:#e8e8e8;--muted:#a2a2a2;--grid:#2c2f36}}
      .Critical{{fill:{SEV_BANDS[0][3]}}} .High{{fill:{SEV_BANDS[1][3]}}}
      .Medium{{fill:{SEV_BANDS[2][3]}}} .Low{{fill:{SEV_BANDS[3][3]}}} .None{{fill:{SEV_BANDS[4][3]}}}
    }}"""

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
           f'viewBox="0 0 {W} {H}" role="img" aria-label="{esc(title)}">',
           f"<style>{css}</style>",
           f'<rect class="bg" x="0" y="0" width="{W}" height="{H}"/>',
           f'<text class="title" x="{pad_l}" y="30">{esc(title)}</text>',
           f'<line class="axis" x1="{pad_l}" y1="{pad_t-6}" x2="{pad_l}" y2="{H-pad_b}"/>']
    y = pad_t
    for label, v in rows:
        bw = max(1, int(plot_w * (v / vmax)))
        cls = f"bar {sev_class(v)}" if color_by == "severity" else "bar"
        vtxt = f"{v:g}"
        out.append(f'<text class="lbl" x="{pad_l-10}" y="{y+row_h*0.68}" '
                   f'text-anchor="end">{esc(trunc(label))}</text>')
        out.append(f'<rect class="{cls}" x="{pad_l}" y="{y}" width="{bw}" '
                   f'height="{row_h}" rx="3"><title>{esc(label)}: {vtxt}</title></rect>')
        out.append(f'<text class="val" x="{pad_l+bw+8}" y="{y+row_h*0.68}">{vtxt}</text>')
        y += row_h + gap
    out.append("</svg>")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="SVG charts from security-analysis CSVs.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bars", help="horizontal ranked bar chart")
    b.add_argument("--csv", required=True)
    b.add_argument("--label", default="path")
    b.add_argument("--value", default="score")
    b.add_argument("--top", type=int, default=10)
    b.add_argument("--title", default="Ranked candidates")
    b.add_argument("--color-by", choices=["accent", "severity"], default="accent")
    b.add_argument("--out", default="")
    args = ap.parse_args()

    rows = read_rows(args.csv, args.label, args.value, args.top)
    if not rows:
        sys.exit("no numeric rows to plot")
    svg = bars_svg(rows, args.title, args.color_by)
    if args.out:
        with open(args.out, "w") as f:
            f.write(svg + "\n")
        print(f"[chart] wrote {args.out}  ({len(rows)} bars)", file=sys.stderr)
    else:
        sys.stdout.write(svg)


if __name__ == "__main__":
    main()
