# cloudsec/pipeline.py

## Purpose

Connects the stages for one file:

    scan -> build input -> prompt -> model -> parse -> pair with findings

and returns every finding with the model's verdict.

## Interface

| Name | Meaning |
|---|---|
| `Model` | Anything with `generate(prompt: str) -> str` |
| `run_file(file, model=None, profile=None)` | Scan with the pinned scanners, then triage |
| `triage(file, findings, model)` | Triage findings already produced |
| `pair(findings, verdicts)` | Match verdicts to findings by check id and occurrence |
| `FileResult` | File, `items` (finding plus verdict), context, raw model text, `unaddressed` count |

## Design decisions

- **The model is an interface.** `None` gives scan-only results; a local
  transformers model serves the i9 functional check; an HTTP client will call
  the triage service. The pipeline does not change between them.
- **No torch import.** CI jobs (GitLab first) can run scan-only without a GPU.
- **Every finding appears in the result.** A finding the model did not address
  keeps `verdict=None` or `label=None` and is counted in `unaddressed`, never as
  FP. Silence scored as FP is the old evaluation defect.
- **Pairing by check id plus occurrence**, so the same rule at two line ranges
  keeps two verdicts.
- **No findings, no model call.** Saves GPU time on clean files.
- **Raw model text is kept** for debugging and audit.

## Tests

`tests/test_pipeline.py`, no GPU:
- A model that answers only the exact training prompts (gold outputs) labels all
  619 findings, 417 TP and 202 FP, with none unaddressed.
- No model: findings returned unchanged, no verdicts.
- Empty model output: every finding unaddressed, none counted as FP.
