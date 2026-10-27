"""GitLab Code Quality report (shown in the merge request widget).

One entry per finding. Confirmed findings carry their severity and fix;
findings the model dismissed stay visible at "info" with the reason.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from cloudsec.pipeline import FileResult, Triaged

SEVERITY = {"critical": "critical", "high": "major", "medium": "minor",
            "low": "minor", "unknown": "minor"}


def gitlab_severity(value: str | None) -> str:
    return SEVERITY.get((value or "unknown").strip().lower(), "minor")


def fingerprint(path: str, tool: str, check_id: str, occurrence: int) -> str:
    """Stable across commits: no line numbers, so edits above a finding keep its identity."""
    return hashlib.sha256(f"{path}|{tool}|{check_id}|{occurrence}".encode()).hexdigest()


def describe(t: Triaged, model_used: bool) -> tuple[str, str]:
    f, v = t.finding, t.verdict
    name = f"{f.title} ({f.check_id})"
    if not model_used:
        return name, gitlab_severity(f.severity)
    if v is None or v.label is None:
        return f"[Not triaged] {name}", gitlab_severity(f.severity)
    if v.label == "FP":
        return f"[Dismissed as FP] {name}. Reason: {v.reason or 'none given'}", "info"
    fix = f" Fix: {v.fix}" if v.fix else ""
    return f"[TP] {name}.{fix}", gitlab_severity(v.severity or f.severity)


def entries(results: list[FileResult]) -> list[dict]:
    out = []
    for r in results:
        model_used = r.raw_output is not None
        seen: Counter[tuple[str, str]] = Counter()
        for t in r.items:
            f = t.finding
            key = (f.tool, f.check_id)
            description, severity = describe(t, model_used)
            out.append({
                "type": "issue",
                "check_name": f"{f.tool}:{f.check_id}",
                "description": description,
                "severity": severity,
                "fingerprint": fingerprint(r.file.path, f.tool, f.check_id, seen[key]),
                "location": {"path": r.file.path, "lines": {"begin": max(1, f.start_line)}},
            })
            seen[key] += 1
    return out


def write(results: list[FileResult], path: str | Path) -> int:
    """Write the report; returns the number of entries."""
    data = entries(results)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(data)
