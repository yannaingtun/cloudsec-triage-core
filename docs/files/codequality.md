# cloudsec/report/codequality.py

## Purpose

Writes pipeline results as a GitLab Code Quality report, which GitLab shows in
the merge request widget (available on the Free tier).

## Interface

| Name | Meaning |
|---|---|
| `entries(results)` | List of Code Quality entries, one per finding |
| `write(results, path)` | Writes the JSON array; returns the entry count |
| `gitlab_severity(value)` | Scanner or model severity to GitLab severity |
| `fingerprint(path, tool, check_id, occurrence)` | Stable id for an issue |

## Mapping

| Case | Severity | Description |
|---|---|---|
| TP | model severity, else scanner | `[TP] title (id). Fix: ...` |
| FP | `info` | `[Dismissed as FP] title (id). Reason: ...` |
| Not addressed by the model | scanner severity | `[Not triaged] title (id)` |
| Scan only (no model) | scanner severity | `title (id)` |

critical -> `critical`, high -> `major`, medium, low, unknown -> `minor`.

## Design decisions

- **Dismissed findings stay visible** at `info` with the model's reason, so a
  reviewer can overrule the model. Nothing is hidden.
- **Unaddressed findings are reported, never dropped** and never shown as FP.
- **Fingerprint excludes line numbers**, so an edit above a finding does not
  turn it into a "new" issue in the MR comparison. The occurrence index keeps
  repeated rules distinct.
- **Report module is separate from the CI adapter.** A SARIF writer for GitHub
  can be added beside it without touching the pipeline.

## Tests

`tests/test_codequality.py`: 619 valid entries with unique fingerprints on the
gold set, 417 TP and 202 FP with FP at `info`, scan-only entries without
verdict tags, severity mapping, and the written file is a JSON array.
