"""GitLab CI entry point: python -m cloudsec.ci.gitlab

Scans every IaC file in the checkout with the pinned scanners and writes a Code
Quality report for the merge request widget. When a model is configured, only
the files the merge request changed are sent to it.

Advisory mode: exit 0 even when findings exist.
Exit 1 if no file could be scanned, 2 if the scanners are not installed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from cloudsec import scan as scanner
from cloudsec.discover import changed_paths, find_iac_files
from cloudsec.pipeline import triage
from cloudsec.report import codequality

# A single unscannable file must not stop the job.
SCAN_ERRORS = (scanner.ScannerError, subprocess.SubprocessError, OSError, KeyError, ValueError)


def main(argv: list[str] | None = None, env: dict | None = None) -> int:
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(prog="python -m cloudsec.ci.gitlab")
    ap.add_argument("--root", default=env.get("CI_PROJECT_DIR", "."))
    ap.add_argument("--report", default="gl-code-quality-report.json")
    ap.add_argument("--profile", help="scanner profile (default: from scanners.toml)")
    args = ap.parse_args(argv)

    profile = args.profile or scanner.default_profile()
    try:
        scanner.tools_dir(profile)
    except scanner.ScannerError as e:
        print(f"cloudsec: {e}", file=sys.stderr)
        return 2

    root = Path(args.root)
    files = find_iac_files(root)

    base = env.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    changed = None
    if base:
        try:
            changed = changed_paths(root, base, env.get("CI_COMMIT_SHA", "HEAD"))
        except RuntimeError as e:
            print(f"cloudsec: warning: {e}", file=sys.stderr)

    model = None  # scan-only until the triage service exists
    results, failed = [], []
    for f in files:
        try:
            findings = scanner.scan_file(f, profile)
        except SCAN_ERRORS as e:
            failed.append(f.path)
            print(f"cloudsec: warning: could not scan {f.path}: {str(e)[:200]}", file=sys.stderr)
            continue
        send = model if changed is None or f.path in changed else None
        results.append(triage(f, findings, send))

    n = codequality.write(results, args.report)
    touched = "n/a (not a merge request)" if changed is None else sum(f.path in changed for f in files)
    print(f"cloudsec: profile {profile}: {len(files)} IaC files, {len(results)} scanned, "
          f"{len(failed)} failed, {n} findings; changed IaC files: {touched}; report: {args.report}")
    return 1 if files and not results else 0


if __name__ == "__main__":
    sys.exit(main())
