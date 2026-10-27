# cloudsec-core documentation

One document per source file, written when the file is built.

## Setup

    cd cloudsec-core
    source .venv/bin/activate     # needed in every new terminal; Python 3.12
    uv pip install -e ".[dev]"
    pytest -q

Without the venv, `pytest` runs under the system Python and fails with
`ModuleNotFoundError: No module named 'cloudsec'`.

## Files

| File | Role | Doc |
|---|---|---|
| `cloudsec/models.py` | Data shapes shared by every stage | [models](files/models.md) |
| `cloudsec/builder.py` | Renders and parses the model input | pending |
| `cloudsec/parse.py` | Reads model output into verdicts | pending |
| `scanners.toml` | Scanner version profiles | pending |
| `scripts/install_scanners.sh` | Installs a profile with checksum verification | pending |
| `scripts/drift_check.py` | Compares a profile's findings with the gold set | pending |
| `cloudsec/prompt.py` | Instruction and prompt template used in training | [prompt](files/prompt.md) |
| `cloudsec/discover.py` | Finds IaC files and changed paths | [discover](files/discover.md) |
| `cloudsec/scan.py` | Runs scanners, returns findings | [scan](files/scan.md) |
| `cloudsec/pipeline.py` | Connects all stages for one file | [pipeline](files/pipeline.md) |
| `cloudsec/report/codequality.py` | GitLab Code Quality report | [codequality](files/codequality.md) |
| `cloudsec/ci/gitlab.py` | GitLab CI entry point | [gitlab](files/gitlab.md) |
| `cloudsec/serve/` | Serves the model over HTTP | [serve](files/serve.md) |
| `docker/Dockerfile` | Scanner image for CI (byte-identical Trivy) | [dockerfile](files/dockerfile.md) |

## Pipeline

    IaC file -> scan.py -> builder.py -> prompt.py -> model -> parse.py -> report
                (Finding)  (input text)          (Verdict)
