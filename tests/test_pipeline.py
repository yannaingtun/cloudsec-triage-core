import json
from collections import Counter
from pathlib import Path

from cloudsec.builder import parse_input
from cloudsec.pipeline import triage
from cloudsec.prompt import build_prompt

DATA = Path(__file__).resolve().parent / "data" / "test.jsonl"
ROWS = [json.loads(line) for line in open(DATA, encoding="utf-8")]


class GoldModel:
    """Returns the gold output; KeyError if the prompt differs from training."""

    def __init__(self):
        self.by_prompt = {build_prompt(r["input"]): r["output"] for r in ROWS}

    def generate(self, prompt):
        return self.by_prompt[prompt]


class EmptyModel:
    def generate(self, prompt):
        return ""


def test_gold_model_labels_every_finding():
    model, labels = GoldModel(), Counter()
    for r in ROWS:
        file, findings = parse_input(r["input"])
        result = triage(file, findings, model)
        assert result.unaddressed == 0
        assert [t.finding for t in result.items] == findings
        labels.update(t.verdict.label for t in result.items)
    assert labels == Counter({"TP": 417, "FP": 202})


def test_no_model_is_scan_only():
    file, findings = parse_input(ROWS[0]["input"])
    result = triage(file, findings, None)
    assert [t.finding for t in result.items] == findings
    assert all(t.verdict is None for t in result.items)
    assert result.raw_output is None


def test_empty_output_is_unaddressed_not_fp():
    file, findings = parse_input(ROWS[0]["input"])
    result = triage(file, findings, EmptyModel())
    assert result.unaddressed == len(findings)
    assert not any(t.verdict and t.verdict.label == "FP" for t in result.items)
