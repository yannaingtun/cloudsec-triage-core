"""parse.py must read every gold output correctly and handle known failure cases."""

import json
from pathlib import Path

from cloudsec.builder import parse_input
from cloudsec.models import Finding
from cloudsec.parse import parse_output

DATA = Path(__file__).parent / "data" / "test.jsonl"


def gold():
    for line in DATA.open(encoding="utf-8"):
        r = json.loads(line)
        _, findings = parse_input(r["input"])
        context, verdicts = parse_output(r["output"], findings)
        yield findings, context, verdicts


# --- against the 38 gold outputs -------------------------------------------

def test_every_gold_finding_is_addressed_with_gold_counts():
    total = tp = fp = 0
    for findings, _, verdicts in gold():
        assert len(verdicts) == len(findings)
        assert all(v.label is not None for v in verdicts)
        total += len(verdicts)
        tp += sum(v.label == "TP" for v in verdicts)
        fp += sum(v.label == "FP" for v in verdicts)
    assert (total, tp, fp) == (619, 417, 202)


def test_tp_has_fix_field_and_fp_has_reason_field():
    empty_fix_rows = set()
    for i, (_, _, verdicts) in enumerate(gold()):
        for v in verdicts:
            if v.label == "TP":
                assert v.fix is not None and v.reason is None
                if v.fix == "":
                    empty_fix_rows.add(i)
            else:
                assert v.reason and v.fix is None
    # Known gold-data gap: row 12 (a Kubernetes StatefulSet) has "Fix:" lines
    # with no text for all its TP findings. Any other empty fix is a parser bug.
    assert empty_fix_rows == {12}


def test_context_parsed_including_wrapped_line():
    contexts = [c for _, c, _ in gold()]
    assert all(c is not None for c in contexts)
    joined = " ".join(f"{c.purpose} {c.environment}" for c in contexts)
    assert "externalizes non" in joined


# --- failure cases from earlier scorers -------------------------------------

def F(check_id):
    return Finding("checkov", check_id, "HIGH", "title", 1, 2)


def test_repeated_ids_match_by_occurrence():
    text = "A: TP [High]\nFix: first\n\nA: FP [Low]\nReason: second"
    v = parse_output(text, [F("A"), F("A")])[1]
    assert [(x.label, x.fix, x.reason) for x in v] == [("TP", "first", None), ("FP", None, "second")]


def test_missing_verdict_is_unaddressed_not_fp():
    v = parse_output("A: TP [High]\nFix: x", [F("A"), F("B")])[1]
    assert v[1].label is None


def test_text_does_not_leak_between_findings():
    v = parse_output("A: FP [High]\n\nB: TP [High]\nFix: only B", [F("A"), F("B")])[1]
    assert v[0].fix is None and v[0].reason is None
    assert v[1].fix == "only B"


def test_unknown_ids_are_ignored():
    v = parse_output("Z: TP [High]\nFix: x", [F("A")])[1]
    assert v[0].label is None


def test_analysis_lines_are_skipped():
    text = "Analysis (A): long reasoning\ncontinued here\nA: TP [Very High]\nFix: do it"
    v = parse_output(text, [F("A")])[1]
    assert (v[0].label, v[0].severity, v[0].fix) == ("TP", "Very High", "do it")
