
# WPA2 M3 — cloudsec-core state (18 Oct 2026)

Full read-through of `cloudsec-core`, a scanner drift measurement across both
dataset splits, a four-arm accuracy experiment settling how to run the pipeline
on current scanners, and a triage service now running on DGX Spark. Scoring
history lives in `claude/evaluation-scoring-defects.md`; dataset design in
`claude/m2-finetuning-status.md`.

## Decisions

**Scanners: this phase stays on the pinned profile (arm B).** Checkov 3.2.495,
Trivy 0.58.2, `scan.py` unchanged. That is what the code already does.

**Running on current scanners is validated and deferred (arm D).** Latest
Checkov and Trivy with two transforms in `scan.py`: Trivy ids rewritten into the
training vocabulary, and Trivy line ranges widened to the enclosing resource.
Confirms 10 more annotated true positives than the pinned profile and gets 12
more verdicts right, at a macro F1 within noise. No retraining, annotation or
dataset regeneration. Adoption steps recorded below.

**Serving: live on Spark since 18 Oct.** `cloudsec/serve/`, containerised,
about 12 tokens per second. Details below.

## What is built

41 tracked files, 38 tests green with zero skips on the i9 and 39 passed with
4 skipped on a fresh aarch64 clone, where the skips are the real-scanner tests
and the cross-repo tripwires.

Six-stage pipeline, one file at a time:

    IaC file -> scan.py -> builder.py -> prompt.py -> model -> parse.py -> report

| Module                    | Role                                                                       |
| ------------------------- | -------------------------------------------------------------------------- |
| `models.py`             | Frozen dataclasses: `IaCFile`, `Finding`, `FileContext`, `Verdict` |
| `scan.py`               | Checkov + Trivy from a pinned profile, training finding order              |
| `builder.py`            | Renders/parses the model input, byte-exact                                 |
| `prompt.py`             | Training instruction and `### Instruction / ### Input / ### Response`    |
| `parse.py`              | Model text to verdicts, one per finding, in input order                    |
| `pipeline.py`           | Connects the stages; model is a `generate(prompt) -> str` Protocol       |
| `discover.py`           | Finds IaC files, and which a merge request changed                         |
| `report/codequality.py` | GitLab Code Quality JSON                                                   |
| `ci/gitlab.py`          | `python -m cloudsec.ci.gitlab`, the only looping entry point             |
| `serve/`                | HTTP triage service, torch behind an optional extra                        |
| `web/`                  | Upload-and-report dashboard (**uncommitted, see below**)             |

**The `Model` Protocol is the seam that made all of this cheap.** `pipeline.py`
does not import torch, so the CI job runs scan-only without a GPU, the
dashboard runs scan-only with no service attached, and the service drops in
behind the same interface with nothing else changing.

The M2 scoring defects are fixed structurally rather than by convention:
`parse_output` iterates the findings list, not the model text, so silence can
never be scored as FP; `Verdict.occurrence` keeps repeated check ids distinct.

## The triage service

Running on `spark-131c`, a DGX Spark: GB10, CUDA 13.0, driver 580.178.04,
aarch64.

`cloudsec/serve/` in cloudsec-core, built from `docker/serve.Dockerfile` on
NVIDIA's `nvcr.io/nvidia/pytorch:25.09-py3` arm64 base, with the weights mounted
read-only rather than baked into a 16 GB layer.

    POST /generate  {"prompt": "..."}  ->  {"text": ..., "seconds": ..., "fingerprint": ...}
    GET  /health                       ->  checkpoint, dtype, device, fingerprint

Serving `Llama-3.1-8B-CloudSec-merged`, fingerprint `7cdeeedb782a736c`,
bfloat16, `cuda:0`, transformers 5.20.1.

### Latency, measured 18 Oct

**572 prompt tokens, 116 generated, 9.8 seconds. About 12 tokens per second.**

Prefill is negligible, so latency scales with the **number of findings**, not
file size: roughly 35 tokens per verdict, so about 3 seconds per finding.

| surface                        | typical           | verdict                                            |
| ------------------------------ | ----------------- | -------------------------------------------------- |
| dashboard upload, ~16 findings | 50 to 70s         | workable with the staged progress indicator        |
| large file, 40+ findings       | 2 minutes or more | needs real progress, not a spinner                 |
| VS Code on save                | same              | too slow to block on; confirms the two-pass design |
| full 38-file arm run           | 40 to 50 min      | against 6.5 and 7.9 hours on a contended H100      |

Twelve tokens per second is about what Spark's memory bandwidth predicts
against an H100's, decode being bandwidth-bound. The win here is not peak speed
but the absence of contention.

If it needs to be faster, **speculative decoding is the option that preserves
comparability**: greedy decoding with exact verification produces token-for-token
identical output, so 0.824 still describes the system. vLLM is faster again and
is a different system; its outputs would need re-measuring before they could sit
beside the arm results.

### Design notes

- **`plan()` is separate from `load()`.** The decisions that silently change
  generated text (dtype, the transformers 4.56 `dtype` rename, adapter
  detection, tokenizer source) are a frozen dataclass computed without torch,
  so they are testable on a machine with no GPU and comparable against
  `infer.py`. `tests/test_serve.py` holds that tripwire, the same arrangement
  `tests/test_prompt.py` uses to pin `PROMPT_TEMPLATE`.
- **torch is not in the `serve` extra.** It is platform-specific and on ARM64
  must come from NVIDIA's build. The Dockerfile asserts at build time that pip
  did not replace the base image's CUDA torch with a CPU wheel, which `peft`
  and `accelerate` would otherwise do silently.
- **Weights mounted, not copied.** The checkpoint changes on its own schedule
  and a 16 GB layer is painful to rebuild.
- **Localhost by default.** `/generate` has no authentication; reach it over an
  SSH tunnel.
- **Provenance in every response.** Checkpoint path and fingerprint on
  `/health` and on every generation.

Deployment check worth keeping: two copies of the weights were on Spark, one
under the pre-rename name `cloudsec-llama31-merged`, which in the M2 notes is
the pre-EOS-fix lineage. Both turned out byte-identical and correct
(`pad=<|finetune_right_pad_id|>`, `eos=<|eot_id|>`, `rope_theta: 500000.0` under
`rope_parameters`, no `chat_template.jinja`). The duplicate was deleted. Check
those four markers on any checkpoint before serving it.

## Scanner drift

`scripts/drift_check.py --profile latest`, both splits.

|                 | Checkov 3.2.495 | Checkov 3.3.16 | Trivy 0.58.2 | Trivy 0.74.0          |
| --------------- | --------------- | -------------- | ------------ | --------------------- |
| test gold       | 320             | 320            | 299          | 299                   |
| exact           | 284             | 284            | 113          | 0                     |
| near            | 36              | 36             | 115          | 256                   |
| missing         | 0               | **0**    | 71           | **43**          |
| train gold      | 2477            | 2477           | 2126         | 2126                  |
| missing (train) | 0               | **0**    | —           | **321 of 2126** |

**Checkov versions are interchangeable.** 3.3.16 reproduced 3.2.495 in every
cell, down to the sub-splits.

**Trivy renamed everything.** `exact 0` is the total rename (`AVD-AWS-0107` to
`AWS-0107`, `KSV001` to `KSV-0001`). Missing drops 71 to 43: the newer scanner
recovers 28 gold findings 0.58.2 cannot produce.

Two facts about the gold Trivy ids, both relevant to `run_trivy`:

- Gold mixes id shapes within a single row: `s3-bucket-logging` and
  `AVD-AWS-0132` appear side by side, and the served model handles both.
  `run_trivy` reads `ID`, the slug form under 0.58.2, so it reproduces the
  first and misses the second. Part of arm B's 71 missing findings and fixable
  independently.
- `AVDID` exists in 0.58.2 and is gone in 0.74.0, so there is no field swap.
  `Namespace` (`builtin.aws.s3.aws0089`) is byte-identical across versions and
  is the reliable cross-version key if one is ever needed.

## The accuracy experiment

Four input sets, each keeping the dataset's `instruction` and `output` and
replacing only `input`. Built by `scripts/build_experiment_inputs.py` and
`scripts/build_arm_d.py`; preserved at `~/Documents/IaC_cicd/experiments-m3/`
on the i9 and `/mnt/sun-data/yannaing/iac-finetune/exp_m3/` on Neptune.

| arm | Checkov       | Trivy         | Trivy ids          | Trivy line ranges             |
| --- | ------------- | ------------- | ------------------ | ----------------------------- |
| A   | dataset's own | dataset's own | gold (control)     | gold                          |
| B   | 3.2.495       | 0.58.2        | fresh, unmodified  | fresh                         |
| C   | 3.3.16        | 0.74.0        | rewritten, 421/436 | fresh (single-line)           |
| D   | 3.3.16        | 0.74.0        | rewritten, 421/436 | widened to enclosing resource |

Scored with `score_triage.py --restrict-to-input`, which scores a gold finding
only if that arm's input still presents it; without it, findings the scanner no
longer reports are charged to the model as triage failures.

### Results

| arm                           | scored | macro F1        | TP f1 | FP f1 | TPs confirmed | correct verdicts |
| ----------------------------- | ------ | --------------- | ----- | ----- | ------------- | ---------------- |
| A gold inputs                 | 619    | 0.857           | 0.909 | 0.805 | 383           | 542              |
| **B pinned (shipping)** | 548    | **0.824** | 0.887 | 0.760 | 331           | 464              |
| C latest + map                | 568    | 0.793           | 0.864 | 0.722 | 329           | 464              |
| D latest + map + widened      | 568    | 0.813           | 0.881 | 0.746 | **341** | **476**    |

Assert-everything baselines are 0.403 / 0.409 / 0.414 / 0.414, so the subset
change is worth about 0.5 points between B and D.

**B is the number to quote for this phase**, since it is the deployed
configuration: pinned scanners, fresh scan, real pipeline. Arm A's 0.857 is
replaying the dataset's own inputs and the M2 table figure is higher still.

### Split by tool — why C failed and D works

|                                                      | A           | B           | C           | D           |
| ---------------------------------------------------- | ----------- | ----------- | ----------- | ----------- |
| Checkov (320, all scored and addressed in every arm) | 0.841       | 0.887       | 0.832       | 0.879       |
| Trivy                                                | 0.872 (299) | 0.730 (228) | 0.731 (248) | 0.720 (248) |

Checkov is the only clean four-way comparison.

**Trivy is flat from B to C**: every Trivy id in C was rewritten and it changed
nothing, so the id map fully neutralises the rename.

**The damage in C landed on Checkov, which nothing touched** — identical
findings, ids not rewritten, yet 5.5 points down. The only difference was the
Trivy block beside them: 436 findings instead of 370, ranges moved from
spanning a resource (`549-562`) to one line (`562-562`).

**Widening recovers 4.7 of those 5.5 points.** The model's verdict on a finding
depends on the shape of the other findings in the list, and line ranges are the
part that matters.

### How to adopt arm D

In `scan.py`, after `run_trivy`:

1. **Rewrite Trivy check ids** using the 157-entry map learned from the train
   split (zero conflicts), with `check_key` normalisation as fallback. Covers
   421 of 436. Map at `~/Documents/IaC_cicd/experiments-m3/map_train.json`;
   regenerate with `drift_check.py --profile latest --data <train split> --map-out`.
2. **Widen each Trivy finding** to the smallest Checkov range from the same
   scan containing its start line. 331 of 436 change; exact agreement with gold
   ranges goes 29% to 64%. Reference implementation in
   `scripts/build_arm_d.py:widen`.

Then set `scanners.toml` to latest and make a version bump a ritual: regenerate
the map, run the drift check, confirm coverage stays above the current 96.6%.

Adopting D also unblocks single-machine hosting, since the pinned Trivy cannot
be installed on aarch64 at all. See below.

## Scanner-independence was tried and is worse

The `blockdata_*` datasets are a different task: the model gets the file plus a
list of resource blocks and no scanner output, and returns vulnerable /
non-vulnerable per block. Immune to drift by construction.

|                | located | F1    | specificity     | macro F1 |
| -------------- | ------- | ----- | --------------- | -------- |
| llama names e8 | 94.3%   | 0.758 | **0.444** | 0.632    |
| qwen names e8  | 91.9%   | 0.759 | **0.634** | 0.678    |
| gemma names e8 | 68.3%   | 0.547 | 0.583           | 0.446    |
| qwen ranges    | 65.9%   | 0.766 | 0.400           | 0.546    |

Best is 0.678 against triage's 0.813, a 13-point cost for dropping the scanner
dependency. A hybrid where block verdicts suppress findings fails on
specificity: at 0.444 it would wrongly keep most of what it should dismiss.
Names beat ranges decisively for identification, 94% and 92% against 66%.

## Arm A came in at 0.857, not 0.875

Under `score_triage.py` the fresh generation scores 0.857 and the archived run7
generations score 0.847, so this environment generates slightly better than the
archive and the gap is the scorer, not the serving path.
`claude/evaluation-scoring-defects.md` names `binary_scores.py` as the M2
authority; `score_triage.py` is a later unification counting silence and
occurrences differently. Two scorers disagree by about 0.02 on identical
generations, which needs settling before publication.

`all_evals.csv` is a third source and should not be used at all: its
`total_findings` reads 357 / 365 / 376 against the test set's 619, because
`evaluate_v3.py`'s allowlist drops every `KSV###` finding. It also has no
dataset column, which is why no older run's provenance can be recovered.

The archived run6 generations score 0.559 with **197 of 619 never addressed**:
the pre-EOS-fix model running to the cap and losing the tail of every response.

## Defect: an unparseable IaC file passes the gate silently

| case              | Checkov exit | stdout  | `parsing_errors` | `run_checkov` |
| ----------------- | ------------ | ------- | ------------------ | --------------- |
| malformed `.tf` | 0            | present | **1**        | `[]`          |
| valid `.tf`     | 1            | present | 0                  | 7 findings      |
| tool failure      | 2            | empty   | n/a                | `[]`          |

Trivy likewise reports an unparseable file as clean, so `check=True` never
fires. `triage()` then returns zero items and `gitlab.py` prints a stderr
warning and never passes the file to `codequality.write`. Malformed IaC, a
raised scanner and a genuinely clean file are indistinguishable in the merge
request widget.

**Fixed on the i9 but not yet committed** (see below): `scan_file` surfaces
Checkov's `summary.parsing_errors`, and `entries()` emits a
`cloudsec:scan-error` issue at `major` for every failed or unparseable file.

## Enrichment is trained, never evaluated, never served

|                   | rows | with an "Additional Findings" section |
| ----------------- | ---- | ------------------------------------- |
| `train.jsonl`   | 310  | **266 (86%)**                   |
| `test.jsonl`    | 38   | 0                                     |
| production inputs | all  | 0                                     |

Step 3 of the instruction, the `NOVEL_` identifiers and nine security
categories, is the majority case in training, absent from every reported figure
and from everything the pipeline sends. The model has a capability nobody has
measured; whether training on 86% enriched inputs primes it to invent that
section is untested; and if it does, `parse.py` drops the verdicts silently and
uncounted. `builder.py` cannot render the section at all, so this is a feature
decision: wire it in and measure it, or record it as dormant.

## Two parsers disagree about what "addressed" means

`score_triage.py:verdict_for` finds a check id anywhere in the text and accepts
a TP or FP within 200 characters. `cloudsec/parse.py` requires an anchored
`^\s*<id>:\s*(TP|FP)\s*(\[sev\])?\s*$`. Every reported figure used the lenient
one; production uses the strict one. The `exp_m3` generations are on disk for
all four arms, so measuring the gap needs no GPU.

The service's first live output parses cleanly under the strict rule, which is
encouraging but is one short response, not a measurement.

## Can one machine host everything? Checked 18 Oct

The question matters because it decides whether HTX can be handed a URL, and
the answer turns out to be coupled to the scanner-version decision.

|                       | amd64 (i9) | aarch64 (Spark)                                             |
| --------------------- | ---------- | ----------------------------------------------------------- |
| Checkov 3.2.495       | yes        | yes (pure Python)                                           |
| Checkov 3.3.16        | yes        | **yes, verified**                                     |
| Trivy 0.74.0          | yes        | **yes, verified**, `Linux-ARM64` asset, checksum OK |
| Trivy 0.58.2 (pinned) | yes        | **no release at all**, source build only              |

So Spark can host the complete pipeline, scanners included, **but only on the
latest profile**. The pinned Trivy release was withdrawn upstream and was never
rebuilt for ARM64, so this phase's shipping configuration is amd64-only.

That is a second argument for arm D independent of accuracy: it collapses a
two-machine arrangement into one.

`install_scanners.sh` now selects the Trivy asset by `uname -m` and fails with
an explanation rather than a bare 404 when the host has no asset (`ff49c7f`).
The same commit removes a half-built `tools/<profile>/` on any failure, which
previously left a working Checkov and no Trivy looking like a valid install.

### Recommended sequencing (proposed, not ratified)

1. **Now.** Dashboard stays a local demo on the i9: scanners local, model
   reached over an SSH tunnel to Spark. No URL, no exposure, nothing to
   maintain.
2. **When HTX actually needs a link.** Move the whole pipeline to Spark behind
   a Cloudflare Tunnel with Access in front. This forces arm D adoption, which
   is wanted anyway.
3. **Never the i9.** A long-lived service on a desktop is a trap: it is the
   machine that gets rebooted, unplugged and reinstalled.

## Repository state, 18 Oct

Two things are loose and worth closing before they bite:

**A day of work exists only on a powered-off i9, uncommitted**: the dashboard
(`cloudsec/web/`), the silent-clean-report fix across `scan.py`,
`codequality.py` and `gitlab.py`, the scanner parallelisation, and their tests.

**The history has forked.** The i9 has three local commits that were never
pushed; Spark has since pushed three commits on top of the same parent, the
most recent being `ff49c7f`. Recovery on the i9:

```bash
git checkout pyproject.toml    # the remote already has that change
git pull --rebase
pytest -q                      # expect 41 passed before the serve work, more after
git push
```

The rebase should be clean: the Spark commits touch `pyproject.toml`,
`cloudsec/serve/`, `tests/test_serve.py`, `scripts/install_scanners.sh` and
`docs/`, while the i9 commits touch `builder.py`, `test_builder.py`,
`drift_check.py` and two scripts.

Three machines now hold copies of this code, and `score_triage.py` was already
patched separately on two of them. Pick GitHub as canonical and have the others
pull rather than edit.

## Remaining work, in priority order

| #  | item                                                                       | where                                                                                                                                    |
| -- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 1  | commit and push the i9 work, rebase the forked history                     | i9                                                                                                                                       |
| 2  | point the dashboard at the service and confirm verdicts render             | `CLOUDSEC_TRIAGE_URL`, SSH tunnel to Spark                                                                                             |
| 3  | unparseable and failed files reach the report (done, uncommitted)          | `scan.py`, `codequality.py`, `gitlab.py`                                                                                           |
| 4  | re-score `exp_m3` generations with `cloudsec/parse.py`                 | no GPU                                                                                                                                   |
| 5  | settle which scorer is authoritative, 0.02 apart                           | `binary_scores.py` vs `score_triage.py`                                                                                              |
| 6  | `run_trivy` reads `ID`; gold mixes `ID` and `AVDID` shapes         | `scan.py`                                                                                                                              |
| 7  | `install_scanners.sh` still cannot install the training profile anywhere | the 0.58.2 release was pulled on every architecture; teach it the Dockerfile's source build. ARM64 asset selection is done (`ff49c7f`) |
| 8  | IAM files are never discovered                                             | `iac_kind` has no IAM branch; the test set's IAM row is structurally CFN, so it does not bite today                                    |
| 9  | no test for the `[Not triaged]` report branch                            | `test_codequality.py`                                                                                                                  |
| 10 | `pair()` re-implements the occurrence rule                               | `pipeline.py`                                                                                                                          |
| 11 | `filename_for` lives in a script three tests import                      | move to `discover.py`                                                                                                                  |
| 12 | five docs still `pending`, `drift_check.py` most of all                | `docs/`                                                                                                                                |

Deferred: adopting arm D, and the 1B student plus distillation work, which is
blocked on Llama 3.2 access approval and has its own plan.

Closed: whether to pin the scanners this phase, whether to rebuild the id map
on `Namespace`, whether a scanner-independent formulation is viable, whether a
dataset regeneration is needed for current scanners, where and how to serve the
model, and whether Spark can run the scanners.

## On hosting cost, for the report

An always-on 24 GB cloud instance (AWS `g6.xlarge`, GCP `g2-standard-4`) is
roughly $0.75 to $1.00 an hour, so $550 to $730 a month, 30 to 40% less on
committed use. But the workload is bursty: minutes of GPU a day against 730
billed hours. Scale-to-zero fixes the economics and costs minutes of cold start
while 16 GB loads.

Against that, Spark is roughly a one-off $4,000 and pays for itself in six or
seven months, with 128 GB rather than 24. For HTX there is also a data handling
question that may rule cloud out independently of price, since the service
receives government infrastructure code.

## Changes made 12–18 Oct

- `builder.py`: `parse_input` skips blank lines, so it reads rows with no
  findings and is a true inverse of `build_input` at zero findings.
- `builder.py`: `ADDITIONAL_HEADER` and `split_additional()`, which is what let
  `drift_check.py` run on `train.jsonl` for the first time despite its docstring
  advertising that command since it was written.
- `score_triage.py`: `--restrict-to-input`, on the i9 and Neptune.
- new `scripts/build_experiment_inputs.py`, `scripts/build_arm_d.py`.
- new `cloudsec/serve/`, `tests/test_serve.py`, `docs/files/serve.md`,
  `docker/serve.Dockerfile`, and the `serve` extra.
- `pyproject.toml`: explicit package discovery, without which a clean clone
  could not install at all.
- `scripts/install_scanners.sh`: architecture-aware Trivy asset selection, and
  removal of a half-built profile directory on failure (`ff49c7f`).
- uncommitted on the i9: `cloudsec/web/`, the scan-error fix, scanner
  parallelisation.

Runtime note: Neptune's eight H100s are heavily shared, so arms C and D took
6.5 and 7.9 hours for 38 examples while arm A took 21 minutes on a quiet card.
Sharding across two partly-free devices did not help. Spark's dedicated 12
tokens per second is slower per token and far more predictable.
