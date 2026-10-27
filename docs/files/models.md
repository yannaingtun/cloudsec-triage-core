# cloudsec/models.py

## Purpose

Defines the data passed between pipeline stages. Plain frozen dataclasses with
no logic, so each stage can be tested and replaced on its own.

## Types

| Type | Meaning | Produced by | Consumed by |
|---|---|---|---|
| `IaCFile` | Repo-relative path and unmodified file text | CI adapter, `parse_input` | `builder` |
| `Finding` | One scanner finding, exactly as shown to the model | `scan`, `parse_input` | `builder`, `parse` |
| `FileContext` | Step 1 of the model output: IaC type, cloud, environment, purpose | `parse` | report |
| `Verdict` | The model's ruling on one finding | `parse` | report, scoring |

A `Finding` renders as:

    - [trivy] AVD-AWS-0132 (HIGH): S3 encryption should use Customer Managed Keys | Lines 16-36

## Design decisions

- **`Verdict.occurrence`.** The same check id can appear at several line ranges
  in one file. Keying on check id alone collapsed these and dropped 6.5% of
  findings in the old scorer. Verdicts are matched by id plus order of
  occurrence.
- **`Verdict.label = None` means unaddressed.** A finding the model never
  mentions is not a prediction of FP. The old scorer treated silence as FP,
  which put an empty-output model near 0.5 macro F1.
- **`fix = ""` versus `fix = None`.** Empty string: the model wrote `Fix:` with
  no text. `None`: no Fix line at all. The report treats both as "no fix
  suggested".
- **`Finding.severity` is the scanner's value.** Checkov without a platform key
  reports `UNKNOWN`; that string is kept because the model was trained on it.
  `Verdict.severity` is separate: it is the model's own assessment.
- **Frozen.** Stages cannot mutate each other's data.

## Tests

No direct tests. Covered through `tests/test_builder.py` (all 38 evaluation
inputs round-trip byte for byte) and `tests/test_parse.py` (619 gold verdicts).
