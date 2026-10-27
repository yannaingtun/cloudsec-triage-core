"""Data shapes shared by every pipeline stage.

Plain dataclasses with no logic. Each stage takes and returns these, so stages
can be tested and replaced independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Label = Literal["TP", "FP"]


@dataclass(frozen=True)
class IaCFile:
    """One infrastructure-as-code file to analyse."""

    path: str      # repo-relative path, e.g. "infra/s3.yaml"
    content: str   # full file text, unmodified


@dataclass(frozen=True)
class Finding:
    """One scanner finding, as rendered in the model input.

    - [trivy] AVD-AWS-0132 (HIGH): S3 encryption should use Customer Managed Keys | Lines 16-36
    """

    tool: str        # "checkov" or "trivy"
    check_id: str    # e.g. "CKV_AWS_18", "s3-bucket-logging", "AVD-AWS-0132"
    severity: str    # scanner severity; Checkov without a platform key reports "UNKNOWN"
    title: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class FileContext:
    """Step 1 of the model output: what the file is."""

    iac_type: str        # e.g. "CFN"
    cloud_provider: str  # e.g. "AWS"
    environment: str     # e.g. "Dev/Test"
    purpose: str


@dataclass(frozen=True)
class Verdict:
    """The model's ruling on one finding."""

    check_id: str
    occurrence: int        # 0 = first time this id appears in the file, 1 = second, ...
    label: Label | None    # None = the model never addressed this finding
    severity: str | None   # model-assigned, e.g. "Medium"
    fix: str | None        # given for TP
    reason: str | None     # given for FP
    # P(TP) from the model's distribution at the label token, when the
    # service measured it. None means not measured, not "uncertain".
    confidence: float | None = None
