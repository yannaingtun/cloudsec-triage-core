# cloudsec/prompt.py

## Purpose

Holds the instruction and prompt template the model was trained on, and
combines them with the builder's input text into the full prompt.

## Interface

| Name | Meaning |
|---|---|
| `INSTRUCTION` | The single training instruction (identical in all 38 test rows) |
| `PROMPT_TEMPLATE` | `### Instruction / ### Input / ### Response` layout |
| `build_prompt(model_input)` | Full prompt for one file |

## Design decisions

- **Plain template, never a chat template.** Training used this bare layout.
  `apply_chat_template()` would produce a format the model never saw, with no
  error. This is also why `chat_template.jinja` is removed from published repos.
- **Instruction generated from the data, not retyped.** The file was written by
  a script from `tests/data/test.jsonl`, so every character (including the dash
  after "Step 1") matches training.
- **Step 3 (Additional Findings) stays in the instruction** although the
  pipeline sends only scanner findings: the model was trained with this exact
  text, and removing it changes the prompt.

## Tests

`tests/test_prompt.py`: instruction equals every training row, prompt layout,
and template equality with `IaC_cicd/repo/infer.py` (skipped when that file is
not present, e.g. in CI).
