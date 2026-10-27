# cloudsec/ci/gitlab.py

## Purpose

Entry point for a GitLab CI job:

    python -m cloudsec.ci.gitlab [--root DIR] [--report FILE] [--profile NAME]

Scans every IaC file in the checkout and writes a Code Quality report
(`gl-code-quality-report.json` by default) for the merge request widget.

## Behaviour

| Step | Detail |
|---|---|
| Check scanners | Profile from `--profile` or `scanners.toml`; missing tools exit 2 |
| Find files | `discover.find_iac_files(CI_PROJECT_DIR)`, all IaC files |
| Changed files | If `CI_MERGE_REQUEST_DIFF_BASE_SHA` is set, `discover.changed_paths` against `CI_COMMIT_SHA` |
| Scan | `scan.scan_file` per file; a failure is a warning and the file is skipped |
| Triage | Changed files go to the model; others are scan-only. No model yet, so all scan-only |
| Report | `report.codequality.write` |

| Exit code | Meaning |
|---|---|
| 0 | Report written (advisory: findings never fail the job) |
| 1 | IaC files exist but none could be scanned |
| 2 | Scanners for the profile are not installed |

## Design decisions

- **Scan everything, triage what changed.** Keeps the MR widget comparison
  correct (see `discover.md`) while limiting GPU work to the change.
- **Advisory first.** The job reports; it does not block merges. Blocking on
  confirmed high-severity TPs can be added once accuracy on HTX repositories
  is known.
- **One bad file does not stop the job**, but a job where nothing could be
  scanned fails, so a broken setup is not reported as "no findings".
- **A shallow clone without the base commit is a warning**, not a failure: the
  report is still complete; only the changed-file selection is lost.
- **`main(argv, env)` takes the environment as a parameter**, so tests run
  without GitLab.

## Known limitations

- `scanners.toml` and `tools/` are read relative to the source checkout; the
  Docker image must keep that layout or set `CLOUDSEC_TOOLS`.
- Files are scanned one at a time; Checkov start-up time dominates on large
  repositories. Parallel scanning is a later optimisation.

## Tests

`tests/test_gitlab.py`: missing scanners (exit 2), one failing file skipped
with a warning, all files failing (exit 1), no IaC files (empty report), MR
pipeline counting changed files while still scanning all, and an end-to-end run
with the real training scanners on a gold file (skipped when not installed).
