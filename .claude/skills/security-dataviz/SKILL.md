---
name: security-dataviz
description: >-
  Produce briefing-grade, dependency-free charts and diagrams from firmware/
  security analysis output for reports and slides. Use when analysis results need
  to be visualized: a ranked bar chart of sink/diff candidates, findings colored
  by CVSS severity, a taint/attack-path flow, or a coordinated-disclosure
  timeline. Triggers: "chart these findings", "visualize the candidates", "graph
  the CVSS scores", "attack path diagram", "disclosure timeline", "make a
  briefing chart", "one-pager for this assessment". Consumes the CSVs from
  firmware-triage / binary-diff and the finding.json from the report skills;
  outputs standalone SVG (theme-aware) and native mermaid. Load the `dataviz`
  skill for palette/design theory; this skill applies it to security data shapes.
---

# Security Dataviz

Turn analysis output into visuals a technical *and* government audience can read
at a glance. Everything is dependency-free and version-controllable: SVG (no JS,
theme-aware, accessible) and mermaid (renders natively on GitHub and in
Artifacts). This serves the communication qualification directly.

## When to use
- You have `sinks.csv` / `diff-candidates.csv` / a findings list / a `finding.json`
  and want a chart, a taint diagram, a timeline, or a one-page briefing.

## Design method
Load the **`dataviz`** skill for the palette, contrast, and accessibility rules —
do not invent a palette. This skill encodes the *security-specific* choices:
severity uses the CVSS bands, rankings sort by score, values are labelled on the
mark. See `reference/chart-selection.md`.

## Workflow

1. **Rank chart** from an analysis CSV:
   ```
   scripts/chart.py bars --csv diff-out/diff-candidates.csv --label path \
       --value score --top 8 --title "Top diff candidates" --out chart.svg
   ```
2. **Severity chart** from a findings CSV (`finding,cvss`):
   ```
   scripts/chart.py bars --csv findings.csv --label finding --value cvss \
       --color-by severity --title "Findings by severity" --out findings.svg
   ```
3. **Taint / attack path** (source -> sink, ends highlighted):
   ```
   scripts/diagram.py taint "QUERY_STRING host" "sprintf() buffer" "doSystem()"
   ```
4. **Disclosure timeline** from the finding:
   ```
   scripts/diagram.py timeline --finding finding.json
   ```
5. **Assemble the briefing** with `templates/briefing-onepager.md` (BLUF ->
   candidates chart -> severity chart -> taint diagram -> timeline ->
   recommendation). Keep it to one page; one idea per chart.

## What "good" looks like
- Charts are sorted by what matters, values labelled, severity uses CVSS bands.
- SVGs render correctly in light and dark and carry an aria-label + tooltips.
- Mermaid renders on GitHub/Artifacts with no external library.
- The one-pager leads with a BLUF a decision-maker can act on.

## Bundled files
- `scripts/chart.py` — standalone theme-aware SVG bar charts from CSV.
- `scripts/diagram.py` — mermaid taint-path + disclosure-timeline generators.
- `templates/briefing-onepager.md` — one-page briefing layout.
- `reference/chart-selection.md` — data-shape -> chart map; defers palette to `dataviz`.
- `examples/` — a rendered severity chart + its input CSV.
