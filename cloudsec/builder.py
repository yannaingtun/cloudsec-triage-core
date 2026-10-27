"""Stage 3: render a file and its scanner findings into the model's input text.

The layout must match the training data byte for byte; a different layout
lowers accuracy without raising any error. tests/test_builder.py checks every
test-set input round-trips exactly.

    IaC File:
    <file content, unmodified>

    Tool Findings:
    - [checkov] CKV_AWS_18 (UNKNOWN): Ensure the S3 bucket has access logging enabled | Lines 16-36
"""

from __future__ import annotations

import re

from cloudsec.models import Finding, IaCFile

FILE_HEADER = "IaC File:\n"
FINDINGS_HEADER = "\n\nTool Findings:\n"

FINDING_LINE = re.compile(
    r"^- \[(?P<tool>\w+)\] (?P<check_id>\S+) \((?P<severity>[^)]*)\): "
    r"(?P<title>.*) \| Lines (?P<start>\d+)-(?P<end>\d+)$"
)


def render_finding(f: Finding) -> str:
    """One finding as a single input line."""
    return f"- [{f.tool}] {f.check_id} ({f.severity}): {f.title} | Lines {f.start_line}-{f.end_line}"


def build_input(file: IaCFile, findings: list[Finding]) -> str:
    """File plus findings, in the training input layout."""
    lines = "\n".join(render_finding(f) for f in findings)
    return FILE_HEADER + file.content + FINDINGS_HEADER + lines


def parse_input(text: str, path: str = "") -> tuple[IaCFile, list[Finding]]:
    """Inverse of build_input. Used by tests and evaluation tooling."""
    if not text.startswith(FILE_HEADER):
        raise ValueError("input does not start with 'IaC File:'")
    k = text.rindex(FINDINGS_HEADER)  # rindex: file content could mention the header
    content = text[len(FILE_HEADER):k]
    findings = []
    for line in text[k + len(FINDINGS_HEADER):].split("\n"):
        m = FINDING_LINE.match(line)
        if not m:
            raise ValueError(f"unrecognised finding line: {line[:120]!r}")
        findings.append(Finding(
            tool=m["tool"], check_id=m["check_id"], severity=m["severity"],
            title=m["title"], start_line=int(m["start"]), end_line=int(m["end"]),
        ))
    return IaCFile(path=path, content=content), findings
