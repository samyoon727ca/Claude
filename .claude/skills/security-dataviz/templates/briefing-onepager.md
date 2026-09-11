# Security Briefing — {{TARGET}} ({{DATE}})

*Audience: technical + government. One page. Every claim traces to evidence.*

## Bottom line up front (BLUF)
> One paragraph: what was assessed, the top risk, and the recommended action.
> A decision-maker should get the point from this alone.

## Attack surface / top candidates
![top candidates](chart-candidates.svg)
<!-- chart.py bars --csv diff-out/diff-candidates.csv --label path --value score --top 8 --title "..." --out chart-candidates.svg -->

## Findings by severity
![findings by severity](chart-findings.svg)
<!-- chart.py bars --csv findings.csv --label finding --value cvss --color-by severity --title "..." --out chart-findings.svg -->

| Finding | CVSS | Class (CWE) | Pre-auth? | Status |
|---------|:----:|-------------|:---------:|--------|
|         |      |             |           |        |

## How the top finding works (taint path)
<!-- diagram.py taint "source" "..." "sink" -->
```mermaid
flowchart LR
    n0["untrusted input"] --> n1["..."] --> n2["dangerous sink"]
```

## Disclosure status
<!-- diagram.py timeline --finding finding.json -->
```mermaid
timeline
    title Coordinated disclosure timeline
    (date) : Reported
```

## Recommendation
> The one or two actions the audience should take (patch, mitigate, prioritize).
