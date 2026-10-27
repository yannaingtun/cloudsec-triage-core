"""Run IaC files through the triage pipeline.

    scan -> build input -> prompt -> model -> parse -> pair with findings

The model is anything with generate(prompt) -> str, so the same pipeline runs
with no model (scan only), a local model, or a remote triage service.
This module does not import torch; CI jobs can use it without a GPU.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Protocol

from cloudsec.builder import build_input
from cloudsec.models import FileContext, Finding, IaCFile, Verdict
from cloudsec.parse import parse_output
from cloudsec.prompt import build_prompt
from cloudsec.scan import scan_file


class Model(Protocol):
    def generate(self, prompt: str) -> str: ...


@dataclass(frozen=True)
class Triaged:
    """One finding with the model's verdict. verdict is None with no model."""

    finding: Finding
    verdict: Verdict | None


@dataclass(frozen=True)
class FileResult:
    file: IaCFile
    items: list[Triaged]
    context: FileContext | None = None
    raw_output: str | None = None  # model text, kept for debugging

    @property
    def unaddressed(self) -> int:
        """Findings with no verdict. Never counted as FP."""
        return sum(1 for t in self.items if t.verdict is None or t.verdict.label is None)


def pair(findings: list[Finding], verdicts: list[Verdict]) -> list[Triaged]:
    """Match verdicts to findings by check id and order of occurrence."""
    by_key = {(v.check_id, v.occurrence): v for v in verdicts}
    seen: Counter[str] = Counter()
    items = []
    for f in findings:
        key = (f.check_id, seen[f.check_id])
        seen[f.check_id] += 1
        items.append(Triaged(finding=f, verdict=by_key.get(key)))
    return items


def triage(file: IaCFile, findings: list[Finding], model: Model | None) -> FileResult:
    """Ask the model about findings already produced. No findings, no model call."""
    if model is None or not findings:
        return FileResult(file=file, items=[Triaged(f, None) for f in findings])
    text = model.generate(build_prompt(build_input(file, findings)))
    context, verdicts = parse_output(text, findings)
    return FileResult(file=file, items=pair(findings, verdicts), context=context, raw_output=text)


def run_file(file: IaCFile, model: Model | None = None, profile: str | None = None) -> FileResult:
    """Scan one file with the pinned scanners, then triage."""
    return triage(file, scan_file(file, profile), model)
