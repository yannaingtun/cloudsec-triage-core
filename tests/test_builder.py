"""builder.py must reproduce the training input format exactly."""

import hashlib
import json
from pathlib import Path

from cloudsec.builder import build_input, parse_input
from cloudsec.models import Finding, IaCFile

DATA = Path(__file__).parent / "data" / "test.jsonl"
EXPECTED_MD5 = "32928b3759821f3aa5f2dc92a1887235"


def rows():
    return [json.loads(line) for line in DATA.open(encoding="utf-8")]


def test_data_is_the_evaluation_test_set():
    assert hashlib.md5(DATA.read_bytes()).hexdigest() == EXPECTED_MD5


def test_every_input_round_trips_exactly():
    for i, r in enumerate(rows()):
        file, findings = parse_input(r["input"], path=f"test-{i}")
        assert build_input(file, findings) == r["input"], f"row {i} differs"


def test_finding_totals_match_gold():
    all_findings = [f for r in rows() for f in parse_input(r["input"])[1]]
    assert len(all_findings) == 619
    assert {f.tool for f in all_findings} <= {"checkov", "trivy"}


def test_build_from_scratch():
    file = IaCFile(path="s3.yaml", content="Resources: {}")
    finding = Finding("trivy", "AVD-AWS-0132", "HIGH",
                      "S3 encryption should use Customer Managed Keys", 16, 36)
    assert build_input(file, [finding]) == (
        "IaC File:\nResources: {}\n\nTool Findings:\n"
        "- [trivy] AVD-AWS-0132 (HIGH): S3 encryption should use Customer Managed Keys | Lines 16-36"
    )
