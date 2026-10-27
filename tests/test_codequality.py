import dataclasses
import json
from pathlib import Path

from cloudsec.builder import parse_input
from cloudsec.pipeline import triage
from cloudsec.prompt import build_prompt
from cloudsec.report.codequality import entries, gitlab_severity, write

DATA = Path(__file__).resolve().parent / "data" / "test.jsonl"
ROWS = [json.loads(line) for line in open(DATA, encoding="utf-8")]
REQUIRED = {"check_name", "description", "severity", "fingerprint", "location"}


class GoldModel:
    def __init__(self):
        self.by_prompt = {build_prompt(r["input"]): r["output"] for r in ROWS}

    def generate(self, prompt):
        return self.by_prompt[prompt]


def gold_results():
    model, results = GoldModel(), []
    for i, r in enumerate(ROWS):
        file, findings = parse_input(r["input"])
        file = dataclasses.replace(file, path=f"infra/row{i:02}.yaml")
        results.append(triage(file, findings, model))
    return results


def test_one_valid_entry_per_finding():
    data = entries(gold_results())
    assert len(data) == 619
    for e in data:
        assert REQUIRED <= e.keys()
        assert e["location"]["path"].startswith("infra/row")
        assert e["location"]["lines"]["begin"] >= 1
    assert len({e["fingerprint"] for e in data}) == 619


def test_fp_is_info_and_tp_is_not():
    data = entries(gold_results())
    fp = [e for e in data if e["description"].startswith("[Dismissed as FP]")]
    tp = [e for e in data if e["description"].startswith("[TP]")]
    assert (len(tp), len(fp)) == (417, 202)
    assert all(e["severity"] == "info" for e in fp)
    assert all(e["severity"] != "info" for e in tp)


def test_scan_only_has_no_verdict_tags():
    file, findings = parse_input(ROWS[0]["input"])
    data = entries([triage(file, findings, None)])
    assert len(data) == len(findings)
    assert not any(e["description"].startswith("[") for e in data)


def test_severity_mapping():
    assert [gitlab_severity(s) for s in ("CRITICAL", "High", "MEDIUM", "LOW", "UNKNOWN", None)] == [
        "critical", "major", "minor", "minor", "minor", "minor"]


def test_write_produces_json_array(tmp_path):
    out = tmp_path / "gl-code-quality-report.json"
    n = write(gold_results()[:2], out)
    assert isinstance(json.loads(out.read_text()), list)
    assert n == len(json.loads(out.read_text()))
