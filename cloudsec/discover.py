"""Find the IaC files to scan in a repository, and which ones a change touched.

Platform-neutral: the GitLab and GitHub adapters both use it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from cloudsec.models import IaCFile

SKIP_DIRS = {".git", ".terraform", "node_modules", ".venv", "venv", "vendor", "__pycache__"}
MAX_BYTES = 1_000_000  # larger files are almost never hand-written IaC

CFN = re.compile(r'^\s*"?(AWSTemplateFormatVersion|Resources)"?\s*:', re.M)
K8S_API = re.compile(r"^apiVersion\s*:", re.M)
K8S_KIND = re.compile(r"^kind\s*:", re.M)


def iac_kind(path: str, text: str) -> str | None:
    """terraform, cloudformation, kubernetes, or None if not IaC we scan."""
    suffix = Path(path).suffix.lower()
    if suffix == ".tf":
        return "terraform"
    if suffix not in (".yaml", ".yml", ".json", ".template"):
        return None
    if CFN.search(text):
        return "cloudformation"  # may contain {{...}} inside strings (e.g. cookiecutter)
    if suffix != ".json" and K8S_API.search(text) and K8S_KIND.search(text):
        if "{{" in text:
            return None  # Helm template: not valid YAML until rendered
        return "kubernetes"
    return None


def find_iac_files(root: str | Path) -> list[IaCFile]:
    """All scannable IaC files under root, with repo-relative POSIX paths, sorted."""
    root = Path(root)
    files = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if not p.is_file() or any(part in SKIP_DIRS for part in rel.parts):
            continue
        if p.stat().st_size > MAX_BYTES:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if iac_kind(str(rel), text):
            files.append(IaCFile(path=rel.as_posix(), content=text))
    return files


def changed_paths(root: str | Path, base: str, head: str = "HEAD") -> set[str]:
    """Paths added, copied, modified or renamed between two commits."""
    out = subprocess.run(["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR", base, head],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"git diff {base} {head} failed: {out.stderr.strip()}. "
                           "In CI, the base commit may be missing from a shallow clone; "
                           "set GIT_DEPTH: 0 or fetch the target branch.")
    return {line for line in out.stdout.splitlines() if line}
