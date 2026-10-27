# docker/Dockerfile

## Purpose

Builds the image the GitLab job runs in: the training-profile scanners
(Checkov 3.2.495, Trivy 0.58.2) plus the cloudsec package, torch-free.

    docker build -f docker/Dockerfile -t cloudsec:dev .

## Stages

| Stage | Base | Does |
|---|---|---|
| `trivy` | `golang:1.23.4` | Clones tag `v0.58.2`, checks commit `936f06a57864d073aa77b38f77fe76c4fcb1f7c1`, builds with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false` |
| runtime | `python:3.12-slim` | git; Checkov in its own venv from `docker/checkov-training.lock`; Trivy from stage 1; cloudsec installed editable; build fails if either version is wrong |

Supporting files: `docker/checkov-training.lock` (the exact Checkov dependency
set from the tested local install, via `uv pip freeze`) and `.dockerignore`
(keeps the local `.git`, `.venv` and `tools/` out of the build context).

## Design decisions

- **Trivy is built from source.** The upstream v0.58.2 release was removed after
  the March 2026 supply-chain incident; the tag remains. Building from the tag
  with a commit check needs no third-party binary.
- **Reproducible build.** Same Go version (1.23.4, read from the local binary)
  and flags as the local build. The image's Trivy is byte-identical to the
  local one: SHA-256 `be7d99cc814a0d21fb4112ea7bde080c79a327575c1ec5290c1d61504fa0cbd5`.
- **Checkov dependencies are locked**, not just Checkov itself; otherwise a
  rebuild would pull newer libraries under the same Checkov version.
- **Empty Trivy cache** (`tools/training/cache`), so Trivy uses the rules built
  into the binary, never a downloaded bundle.
- **Same layout as a source checkout** (`/opt/cloudsec/{scanners.toml,tools/,cloudsec/}`),
  installed editable, so `scan.py` finds everything without configuration.
- **No torch.** The CI job is scan-only until the triage service exists.
- **No ENTRYPOINT**, so GitLab can run job scripts in the image's shell.

## Verification (1 Oct 2026)

| Check | Result |
|---|---|
| Trivy SHA-256 versus local build | identical |
| Versions | Checkov 3.2.495, Trivy 0.58.2, no check bundle |
| `scripts/drift_check.py` in the container | identical to local (Checkov 284/14/22/0/57, Trivy 113/2/113/71/142) |

To repeat the drift check:

    docker run --rm -v "$PWD/scripts:/opt/cloudsec/scripts:ro" \
      -v "$PWD/tests:/opt/cloudsec/tests:ro" cloudsec:dev python scripts/drift_check.py

## Known limitations

- Runs as root, which suits GitLab's Docker executor. Revisit if HTX runners
  require non-root images.
- The first build takes about 6 minutes, mostly the Go build.
- `install_scanners.sh training` still points at the removed upstream release;
  the image does not use it.
