"""The exact prompt format the model was trained on.

A plain instruction template, not a chat template. The model was never trained
on a chat template, and apply_chat_template() would silently produce a format
it has not seen. Must match PROMPT_TEMPLATE in IaC_cicd/repo/infer.py.
"""

# Copied byte for byte from the training data; tests/test_prompt.py checks it.
INSTRUCTION = "\n\n".join([
    'You are an IaC security expert. Given an IaC file and its tool findings:',
    'Step 1 — Identify the file context: - IaC Type: Terraform / CloudFormation / Kubernetes / IAM - Cloud Provider: AWS / GCP / Azure / Other - Environment: Production / Development / Unknown - Purpose: briefly describe what this file provisions',
    'Step 2 — Classify each finding as TP (True Positive) or FP (False Positive). Use the file context from Step 1 to inform your reasoning. Default to TP unless there is clear and specific evidence the finding is a false positive. For TP: provide a specific suggested fix. For FP: provide a clear reason explaining why it is a false positive.',
    'Step 3 — If the input includes an "Additional Findings" section, these are issues the tools did not report. Classify each one the same way, echo its NOVEL_ identifier exactly as given, and assign one security category from: Access Control, Availability, Compliance, Data Protection, Encryption, Hardening, Logging/Monitoring, Network Security, Secrets Management.',
])

PROMPT_TEMPLATE = (
    "### Instruction:\n{instruction}\n\n"
    "### Input:\n{input}\n\n"
    "### Response:\n"
)


def build_prompt(model_input: str, instruction: str = INSTRUCTION) -> str:
    """Full prompt for one file: instruction plus the text from builder.build_input."""
    return PROMPT_TEMPLATE.format(instruction=instruction, input=model_input)
