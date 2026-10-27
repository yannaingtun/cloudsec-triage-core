"""Stage 5: turn the model's output text into file context and verdicts.

Expected output:

    IaC Type: CFN
    Cloud Provider: AWS
    Environment: Dev/Test
    Purpose: Creates an encrypted, versioned, private S3 bucket

    CKV_AWS_18: TP [Medium]
    Fix: Add a LoggingConfiguration property pointing to a separate log bucket

    AVD-AWS-0132: FP [Medium]
    Reason: The bucket already uses SSE-S3 AES256 encryption

Rules, each fixing a failure seen in earlier scorers:
- Repeated check ids are matched to findings by order of occurrence.
- A finding with no verdict line is returned with label=None, never as FP.
- Fix/Reason text belongs only to the verdict directly above it.
- A line with no key continues the field above it (long Purpose or Fix).
- "Analysis (ID):" lines are skipped, so a reasoning-first format still parses.
"""

from __future__ import annotations

import re
from collections import defaultdict

from cloudsec.models import FileContext, Finding, Verdict

HEADER_KEYS = {
    "IaC Type": "iac_type",
    "Cloud Provider": "cloud_provider",
    "Environment": "environment",
    "Purpose": "purpose",
}
FIELD_LINE = re.compile(r"^\s*(?P<key>Fix|Reason):\s*(?P<text>.*)$")
VERDICT_LINE = re.compile(
    r"^\s*(?P<check_id>\S+):\s*(?P<label>TP|FP)\s*(?:\[(?P<severity>[^\]]*)\])?\s*$"
)
ANALYSIS_LINE = re.compile(r"^\s*Analysis\s*\([^)]*\):")


def _read(text: str) -> tuple[dict[str, list[str]], list[dict]]:
    """Split output into header fields and raw verdict entries, in order."""
    header: dict[str, list[str]] = {}
    entries: list[dict] = []
    target: list[str] | None = None  # where continuation lines go

    for line in text.split("\n"):
        if not line.strip():
            # Header fields (before any verdict) may continue after a blank line,
            # e.g. a Purpose written as two paragraphs.
            if entries:
                target = None
            continue

        key = line.split(":", 1)[0].strip()
        if not entries and ":" in line and key in HEADER_KEYS:
            target = header[HEADER_KEYS[key]] = [line.split(":", 1)[1].strip()]
            continue

        m = FIELD_LINE.match(line)
        if m and entries:
            target = entries[-1][m["key"]] = [m["text"].strip()]
            continue

        if ANALYSIS_LINE.match(line):
            target = None
            continue

        m = VERDICT_LINE.match(line)
        if m:
            entries.append({"check_id": m["check_id"], "label": m["label"],
                            "severity": m["severity"], "Fix": None, "Reason": None})
            target = None
            continue

        if target is not None:
            target.append(line.strip())

    return header, entries


def _join(parts: list[str] | None) -> str | None:
    return " ".join(parts) if parts else None


def parse_output(text: str, findings: list[Finding]) -> tuple[FileContext | None, list[Verdict]]:
    """Return the file context and exactly one Verdict per input finding, in input order."""
    header, entries = _read(text)

    context = None
    if all(k in header for k in HEADER_KEYS.values()):
        context = FileContext(**{k: _join(v) for k, v in header.items()})

    by_key: dict[tuple[str, int], dict] = {}
    seen: defaultdict[str, int] = defaultdict(int)
    for e in entries:
        cid = e["check_id"].upper()
        by_key.setdefault((cid, seen[cid]), e)
        seen[cid] += 1

    verdicts = []
    count: defaultdict[str, int] = defaultdict(int)
    for f in findings:
        cid = f.check_id.upper()
        occ = count[cid]
        count[cid] += 1
        e = by_key.get((cid, occ))
        verdicts.append(Verdict(
            check_id=f.check_id,
            occurrence=occ,
            label=e["label"] if e else None,
            severity=e["severity"] if e else None,
            fix=_join(e["Fix"]) if e else None,
            reason=_join(e["Reason"]) if e else None,
        ))
    return context, verdicts
