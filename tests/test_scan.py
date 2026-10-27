import importlib.util
import json
from pathlib import Path

import pytest

from cloudsec import scan
from cloudsec.builder import parse_input
from cloudsec.models import Finding, IaCFile

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests/data/test.jsonl"


def f(tool, line, cid="X"):
    return Finding(tool=tool, check_id=cid, severity="HIGH", title="t",
                   start_line=line, end_line=line)


def test_default_profile_is_training():
    assert scan.default_profile() == "training"


def test_order_is_checkov_block_then_trivy_block_stable():
    got = scan.order_findings([f("trivy", 16, "a"), f("checkov", 74),
                               f("trivy", 16, "b"), f("checkov", 16)])
    assert [(x.tool, x.start_line, x.check_id) for x in got] == [
        ("checkov", 74, "X"), ("checkov", 16, "X"), ("trivy", 16, "a"), ("trivy", 16, "b")]


# Gold rows built with a different convention (line- or resource-based order).
# Any change to this set means the data or the rule changed.
OTHER_ORDER_ROWS = {1, 5, 7, 9, 10, 36}


def test_gold_inputs_follow_the_training_order_except_known_rows():
    other = set()
    for i, line in enumerate(open(DATA, encoding="utf-8")):
        _, findings = parse_input(json.loads(line)["input"])
        if scan.order_findings(findings) != findings:
            other.add(i)
    assert other == OTHER_ORDER_ROWS


def _installed(profile="training"):
    try:
        scan.tools_dir(profile)
        return True
    except scan.ScannerError:
        return False


@pytest.mark.skipif(not _installed(), reason="training scanners not installed")
def test_scan_row0_reproduces_gold_checkov():
    spec = importlib.util.spec_from_file_location("drift_check", ROOT / "scripts/drift_check.py")
    dc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dc)

    r = json.loads(open(DATA, encoding="utf-8").readline())
    file, gold = parse_input(r["input"])
    iac_type = r["output"].split("\n", 1)[0].split(":", 1)[1].strip()
    name = dc.filename_for(iac_type, file.content)

    got = scan.scan_file(IaCFile(path=name, content=file.content), profile="training")
    assert got == scan.order_findings(got)
    assert [x for x in got if x.tool == "checkov"] == [x for x in gold if x.tool == "checkov"]
    assert any(x.tool == "trivy" for x in got)
