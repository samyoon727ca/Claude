# Vulnerability Report: {{title}}

**Vendor:** {{vendor}}
**Researcher:** {{researcher}}{{contact}}
**Vulnerability type:** {{vuln_type}} ({{cwe}} — {{cwe_name}})
**Affected component:** {{component}}
**Severity:** {{cvss_score}} ({{cvss_severity}}), `{{cvss_vector}}`
**Preconditions:** {{preconditions}}

> Coordinated disclosure. This report is confidential until a fix is available or
> the agreed disclosure window closes. Reported {{reported_date}}; requested public
> disclosure target: {{target_public}}.

## Affected products

{{products_table}}

## Summary

{{description}}

## Steps to reproduce

{{repro_steps_md}}

## Impact

{{impact}}

## Severity justification (CVSS v3.1)

Base score **{{cvss_score}} ({{cvss_severity}})** — `{{cvss_vector}}`.
The vector reflects the preconditions above; see the per-metric rationale the
researcher provides with this report.

## Suggested remediation

{{remediation}}

## Discovery

{{discovery_method}}

---
*Reported under coordinated disclosure. Please acknowledge receipt and provide a
tracking identifier. The researcher is available to verify a candidate fix.*
