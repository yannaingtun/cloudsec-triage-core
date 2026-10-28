"""The canonical record of one execution, and how to file it.

Every report is a projection of this: GitLab Code Quality, the dashboard, the
CLI. The collector stores this shape, so adding a renderer never changes the
schema and changing a renderer never loses history.

What makes a stored run still interpretable later is the provenance, not the
findings: which scanners produced them and which checkpoint judged them. Both
go on every run. all_evals.csv recorded neither, which is why no older run can
be traced to its dataset.
"""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from cloudsec.pipeline import FileResult
from cloudsec.scan import default_profile, tools_dir


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_run_id() -> str:
    """Random, not derived from the file.

    The same file is uploaded repeatedly and two files share a name across
    projects, so a content- or name-derived key would collide. The content
    hash is stored separately, which is what answers "have I seen these exact
    bytes under this exact config before".
    """
    return uuid.uuid4().hex


def _version(path, *args) -> str | None:
    try:
        out = subprocess.run([str(path), *args], capture_output=True,
                             text=True, timeout=30)
        return (out.stdout or out.stderr).strip().splitlines()[0].strip() or None
    except Exception:
        return None


def scanner_versions(profile: str) -> tuple[str | None, str | None]:
    try:
        b = tools_dir(profile)
    except Exception:
        return None, None
    ck = _version(b / "checkov", "--version")
    tv = _version(b / "trivy", "--version")
    if tv and tv.lower().startswith("version:"):
        tv = tv.split(":", 1)[1].strip()
    return ck, tv


def ci_meta() -> dict:
    """GitLab CI variables, when running inside a job.

    The pipeline id goes in external_ref rather than the key, because a
    retried job is a new run that shares a reference.
    """
    e = os.environ
    ref = e.get("CI_JOB_ID") or e.get("CI_PIPELINE_ID")
    return {
        "source": "ci" if ref else "cli",
        "external_ref": ref,
        "project": e.get("CI_PROJECT_PATH"),
        "branch": e.get("CI_COMMIT_REF_NAME"),
        "commit_sha": e.get("CI_COMMIT_SHA"),
    }


def build_run(results: list[FileResult], *, profile: str | None = None,
              service: dict | None = None, seconds: float | None = None,
              source: str | None = None, **over) -> dict:
    profile = profile or default_profile()
    checkov, trivy = scanner_versions(profile)
    meta = ci_meta()
    if source:
        meta["source"] = source

    files = []
    for r in results:
        ctx = r.context
        files.append({
            "path": r.file.path,
            "content_sha256": sha256(r.file.content),
            "context": ({"iac_type": ctx.iac_type,
                         "cloud_provider": ctx.cloud_provider,
                         "environment": ctx.environment,
                         "purpose": ctx.purpose} if ctx else None),
            "raw_output": r.raw_output,
            "content": r.file.content,
            "findings": [{
                "tool": t.finding.tool,
                "check_id": t.finding.check_id,
                "occurrence": t.verdict.occurrence if t.verdict else 0,
                "severity": t.finding.severity,
                "title": t.finding.title,
                "start_line": t.finding.start_line,
                "end_line": t.finding.end_line,
                "label": t.verdict.label if t.verdict else None,
                "verdict_severity": t.verdict.severity if t.verdict else None,
                "fix": t.verdict.fix if t.verdict else None,
                "reason": t.verdict.reason if t.verdict else None,
                "confidence": getattr(t.verdict, "confidence", None) if t.verdict else None,
                "confidence_source": ("logprob"
                                      if t.verdict is not None
                                      and getattr(t.verdict, "confidence", None) is not None
                                      else None),
            } for t in r.items],
        })

    run = {
        "run_id": new_run_id(),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": profile,
        "checkov_version": checkov,
        "trivy_version": trivy,
        "model": (service or {}).get("model"),
        "model_fingerprint": (service or {}).get("fingerprint"),
        "transformers": (service or {}).get("transformers"),
        "seconds": seconds,
        "client": socket.gethostname(),
        "files": files,
        **meta,
    }
    run.update(over)
    return run


def post_run(collector_url: str, run: dict, timeout: float = 30) -> str | None:
    """File the run. Never raises: a lost record must not fail a scan."""
    import json

    req = urllib.request.Request(
        collector_url.rstrip("/") + "/runs",
        data=json.dumps(run).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()).get("run_id")
    except Exception as e:
        print(f"[warn] could not file run with collector: {e}")
        return None
