"""Run the pinned scanners on one IaC file.

Returns findings in the order most training inputs used (32 of 38 test
files): all Checkov findings, then all Trivy findings, each in the scanner's
own order. No sorting by line.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import tomllib
from pathlib import Path

from cloudsec.models import Finding, IaCFile

ROOT = Path(__file__).resolve().parent.parent
TOOL_ORDER = {"checkov": 0, "trivy": 1}
TIMEOUT = 300  # seconds per scanner call


class ScannerError(RuntimeError):
    """Scanners are missing or failed."""


def default_profile(root: Path = ROOT) -> str:
    with open(root / "scanners.toml", "rb") as f:
        cfg = tomllib.load(f)
    if isinstance(cfg.get("default"), str):
        return cfg["default"]
    for value in cfg.values():
        if isinstance(value, dict) and isinstance(value.get("default"), str):
            return value["default"]
    raise ScannerError("scanners.toml has no default profile")


def tools_dir(profile: str) -> Path:
    """bin/ folder of an installed profile. CLOUDSEC_TOOLS overrides the base (for Docker)."""
    base = Path(os.environ.get("CLOUDSEC_TOOLS", ROOT / "tools"))
    bin_dir = base / profile / "bin"
    if not (bin_dir / "checkov").exists() or not (bin_dir / "trivy").exists():
        raise ScannerError(f"profile '{profile}' not installed in {bin_dir}; "
                           f"run scripts/install_scanners.sh {profile}")
    return bin_dir


def run_checkov(bin_dir: Path, path: Path) -> list[Finding]:
    # Checkov exits 1 when checks fail, so the exit code is not an error signal.
    out = subprocess.run([str(bin_dir / "checkov"), "-f", str(path), "-o", "json", "--quiet"],
                         capture_output=True, text=True, timeout=TIMEOUT)
    if not out.stdout.strip():
        return []
    data = json.loads(out.stdout)
    found = []
    for block in data if isinstance(data, list) else [data]:
        for x in block.get("results", {}).get("failed_checks", []):
            start, end = x["file_line_range"]
            found.append(Finding(tool="checkov", check_id=x["check_id"],
                                 severity=x.get("severity") or "UNKNOWN",
                                 title=x["check_name"], start_line=start, end_line=end))
    return found


def run_trivy(bin_dir: Path, folder: Path) -> list[Finding]:
    # --skip-check-update keeps the rules built into the pinned binary.
    out = subprocess.run([str(bin_dir / "trivy"), "config", "--skip-check-update",
                          "--cache-dir", str(bin_dir.parent / "cache"),
                          "--format", "json", "--quiet", str(folder)],
                         capture_output=True, text=True, timeout=TIMEOUT, check=True)
    found = []
    for res in json.loads(out.stdout).get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            cm = m.get("CauseMetadata") or {}
            found.append(Finding(tool="trivy", check_id=m.get("ID"),
                                 severity=m.get("Severity"), title=m.get("Title"),
                                 start_line=cm.get("StartLine", 0),
                                 end_line=cm.get("EndLine", 0)))
    return found


def order_findings(findings: list[Finding]) -> list[Finding]:
    """Training order: Checkov block, then Trivy block; scanner order kept (stable sort)."""
    return sorted(findings, key=lambda f: TOOL_ORDER.get(f.tool, 99))


def scan_file(file: IaCFile, profile: str | None = None) -> list[Finding]:
    """Scan one file in isolation, as the training data was produced."""
    bin_dir = tools_dir(profile or default_profile())
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / Path(file.path).name
        path.write_text(file.content, encoding="utf-8")
        found = run_checkov(bin_dir, path) + run_trivy(bin_dir, Path(tmp))
    return order_findings(found)
