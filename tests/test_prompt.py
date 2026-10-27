import ast
import json
from pathlib import Path

import pytest

from cloudsec.prompt import INSTRUCTION, PROMPT_TEMPLATE, build_prompt

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests/data/test.jsonl"
INFER = ROOT.parent / "repo" / "infer.py"


def test_instruction_matches_every_training_row():
    rows = [json.loads(line) for line in open(DATA, encoding="utf-8")]
    assert {r["instruction"] for r in rows} == {INSTRUCTION}


def test_prompt_layout():
    r = json.loads(open(DATA, encoding="utf-8").readline())
    assert build_prompt(r["input"]) == (
        f"### Instruction:\n{r['instruction']}\n\n"
        f"### Input:\n{r['input']}\n\n"
        "### Response:\n")


@pytest.mark.skipif(not INFER.exists(), reason="IaC_cicd/repo/infer.py not available")
def test_template_matches_infer_py():
    for node in ast.walk(ast.parse(INFER.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "PROMPT_TEMPLATE" for t in node.targets):
            assert ast.literal_eval(node.value) == PROMPT_TEMPLATE
            return
    pytest.fail("PROMPT_TEMPLATE not found in infer.py")
