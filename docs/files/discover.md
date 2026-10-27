# cloudsec/discover.py

## Purpose

Finds the IaC files to scan in a repository, and which files a change touched.
Platform-neutral: the GitLab adapter uses it now, a GitHub adapter later.

## Interface

| Function | Returns |
|---|---|
| `find_iac_files(root)` | Every scannable IaC file as `IaCFile`, repo-relative POSIX path, sorted |
| `iac_kind(path, text)` | `terraform`, `cloudformation`, `kubernetes`, or `None` |
| `changed_paths(root, base, head="HEAD")` | Paths added, copied, modified or renamed |

## Detection rules

| Kind | Rule |
|---|---|
| Terraform | `.tf` |
| CloudFormation | `.yaml`, `.yml`, `.json`, `.template` with a line starting `AWSTemplateFormatVersion:` or `Resources:` (quoted keys allowed) |
| Kubernetes | `.yaml`, `.yml` with top-level `apiVersion:` and `kind:`, and no `{{` |

Skipped: `.git`, `.terraform`, `node_modules`, `.venv`, `venv`, `vendor`,
`__pycache__`, files over 1 MB, files that are not UTF-8.

## Design decisions

- **Scan scope versus triage scope.** GitLab's MR widget compares the MR report
  with the target branch report by fingerprint. If an MR scanned only changed
  files, every issue in unchanged files would appear "fixed". So every pipeline
  scans all IaC files, and `changed_paths` selects which files go to the model.
- **Helm skip applies to Kubernetes only.** A Helm template is not valid YAML
  until rendered. CloudFormation is checked first, because templates such as
  test row 11 hold `{{cookiecutter...}}` inside JSON strings and scan normally.
  This was caught by the gold-file test.
- **`--diff-filter=ACMR`.** Deleted files have nothing to scan.
- **A clear error for shallow clones.** CI clones are shallow; if the base commit
  is missing, the error names the fix (`GIT_DEPTH: 0` or fetching the target
  branch).

## Tests

`tests/test_discover.py`: a synthetic repository (Terraform, Kubernetes, CFN
YAML and JSON, cookiecutter CFN, Helm, non-IaC YAML, skipped folders, an
oversized file); all 38 gold files detected; changed paths across a commit
with a modify, an add and a delete; the shallow-clone error message.
