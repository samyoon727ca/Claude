# Choosing the Right Chart/Diagram for Security Data

Palette and general design method: **load the `dataviz` skill** — it carries the
validated palette and the accessibility rules. This file maps the *specific data
shapes of a firmware assessment* to the right visual, so the briefing reads as
senior work rather than decoration.

## Match the data to the mark
| You have | Use | Command |
|----------|-----|---------|
| Ranked candidates (sinks.csv / diff-candidates.csv: label + score) | Horizontal bar, sorted desc, top N | `chart.py bars --value score` |
| Findings with CVSS scores | Horizontal bar, `--color-by severity` (bands = CVSS) | `chart.py bars --value cvss --color-by severity` |
| Firmware diff totals (added/removed/changed) | Small bar of the three counts | `chart.py bars` on a 3-row CSV |
| A taint / attack path (source -> sink) | Mermaid flowchart, ends highlighted | `diagram.py taint ...` |
| Coordinated-disclosure dates | Mermaid timeline | `diagram.py timeline --finding finding.json` |

## Principles (applied to these charts)
- **Sort by the thing that matters** (score/severity), never alphabetically — the
  reader's eye should land on the top risk first.
- **Label values directly** on the bars; do not make the reader estimate against
  an axis. `chart.py` writes the value at each bar end.
- **Encode severity with the CVSS bands**, not arbitrary colors, so the color
  means the same thing every time (Critical/High/Medium/Low/None).
- **Theme-aware + accessible:** the SVGs carry both light/dark palettes via
  `prefers-color-scheme`, an `aria-label`, and `<title>` tooltips — they read
  correctly on GitHub, in a slide, and in a dark-mode report.
- **One idea per chart.** A briefing has several small, clear charts, not one
  dense one.

## Do not
- Do not use a pie chart for rankings (bars compare lengths far better).
- Do not 3-D anything.
- Do not invent a color scale for severity — reuse the CVSS bands here.
