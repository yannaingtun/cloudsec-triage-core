# cloudsec/serve/

## Purpose

Serves the fine-tuned model over HTTP, so the dashboard, the CI adapter and any
editor integration reach it the same way.

    POST /generate  {"prompt": "..."}  ->  {"text": "...", ...}
    GET  /health                       ->  checkpoint, dtype, device, fingerprint

## Interface

| Name | Meaning |
|---|---|
| `model.plan(path, transformers_version, ...)` | Resolves the loading decisions; pure, no torch |
| `model.load(plan)` | Applies the plan; imports torch and transformers |
| `model.fingerprint(path)` | Cheap checkpoint identity, for provenance |
| `app:app` | FastAPI application, configured by `CLOUDSEC_*` environment variables |

## Design decisions

- **Loaded once.** `infer.py` pays about three and a half minutes of weight
  loading on every run; the service pays it at startup.
- **`plan()` is separate from `load()`.** The decisions that silently change
  generated text (dtype, the transformers 4/5 dtype keyword, adapter detection,
  tokenizer source) are a frozen dataclass computed without torch, so they can
  be tested on a machine with no GPU and compared against `infer.py`.
- **Serialised generation.** One resident model is the resource, and the arm
  experiments measured one sequence at a time. Requests past `MAX_QUEUE` get
  503 rather than queueing without limit.
- **torch is not in the `serve` extra.** It is platform-specific, and on ARM64
  it must come from NVIDIA's build rather than PyPI.
- **Localhost by default.** `/generate` has no authentication; reach it over an
  SSH tunnel.
- **Provenance in every response.** `/health` and each `/generate` carry the
  checkpoint path and fingerprint, so a verdict can be traced to the weights
  that produced it.

## Known limitations

vLLM would be faster and would also be a different system: its outputs would
have to be re-measured before they could be compared with the arm results.

## Tests

`tests/test_serve.py`: the dtype keyword either side of the transformers 4.56
rename, merged versus adapter resolution, tokenizer source, dtype validation,
and a tripwire comparing the loading decisions against `IaC_cicd/repo/infer.py`
when that repo sits beside this one (skipped otherwise).
