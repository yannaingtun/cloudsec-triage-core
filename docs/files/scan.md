# cloudsec/scan.py

## Purpose

Runs Checkov and Trivy from a pinned profile on one IaC file and returns
`Finding` objects in the order used by most training inputs.

## Interface

| Function | Returns |
|---|---|
| `scan_file(file, profile=None)` | Findings for one `IaCFile`; profile defaults to `scanners.toml` |
| `default_profile()` | Default profile name (`training`) |
| `tools_dir(profile)` | `tools/<profile>/bin`; `CLOUDSEC_TOOLS` overrides the base path |
| `run_checkov`, `run_trivy` | Raw findings from one scanner; also used by `scripts/drift_check.py` |
| `order_findings(findings)` | Checkov block, then Trivy block, scanner order kept |

## Design decisions

- **Training profile by default** (Checkov 3.2.495, Trivy 0.58.2). The published
  model (macro F1 0.875) was measured on inputs from these versions. The latest
  scanners rename every Trivy id and add many findings; they need a retrained
  model first.
- **Trivy `--skip-check-update` and a per-profile cache.** Otherwise Trivy
  downloads the newest rule bundle and the pinned version means nothing.
- **Each file is scanned alone in a temp folder.** Trivy scans a folder, so an
  isolated copy guarantees only this file is scanned and the content is exactly
  what the model sees. This matches how the training data was produced.
- **No deduplication, no filtering.** Findings are reported per resource.
- **Checkov severity `None` becomes `UNKNOWN`**, the string the model was trained on.
- **Order: all Checkov, then all Trivy, no sorting by line.** Checked on the 38
  gold inputs: this fits 32, sorting by line fits 30. Rows 1, 5, 7, 9, 10 and 36
  use a different convention (line- or resource-based) and cannot be reproduced;
  the test pins this exact set.
- **One source of scanner logic.** `scripts/drift_check.py` calls `run_checkov`
  and `run_trivy` from this module, so the drift check tests production code.

## Known limitations

Fresh scans do not reproduce the training inputs byte for byte (training
profile, 38 test files, 30 Sep 2026):

| Tool | Gold | Exact | Same check, different wording/lines | Missing | New |
|---|---|---|---|---|---|
| Checkov | 320 | 284 | 36 | 0 | 57 |
| Trivy | 299 | 113 | 115 | 71 | 142 |

The Trivy gap matches a newer rule bundle used when the training data was
produced (e.g. `Ignore Public ACL` versus `Acl`; `AVD-AWS-0066` and
`AVD-AWS-0345` absent from 0.58.2's built-in rules). Ordering differs in 6 of 38
files. The release gate is therefore end-to-end triage accuracy, not byte-exact
input reproduction.

Terraform files that depend on variables or modules in other files are scanned
without them, as in training. An empty Checkov output is treated as no findings.

## Tests

`tests/test_scan.py`: default profile, ordering rule (synthetic and all 38 gold
inputs with the 6 known exceptions), and a scan of row 0 with the training
profile (skipped when scanners are not installed).
`python scripts/drift_check.py` compares all 38 files with the gold findings.
