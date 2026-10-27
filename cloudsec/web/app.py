"""Dashboard: upload an IaC file, see its findings triaged.

A thin layer over cloudsec.client. Scanning and generation take a minute or
more for a real file, so the work runs in a background thread and the browser
polls. A request that blocks that long dies to proxy timeouts and says nothing
useful while it waits.

Jobs live in memory and are lost on restart. Finished runs are kept in a
SQLite store: written directly with --db (no separate process), or posted to
a standalone collector with --collector. Use one or the other, not both.

    CLOUDSEC_TRIAGE_URL=http://127.0.0.1:8100 \
    CLOUDSEC_DB=runs.db \
    python -m cloudsec.web.app
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import urllib.request
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from cloudsec import client as triage_client
from cloudsec import runs as runs_mod
from cloudsec.collector import store as run_store
import datetime

HERE = Path(__file__).parent
MAX_BYTES = 2_000_000          # an IaC file is kilobytes; this is a guard, not a limit
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


def cfg(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def _set(job_id: str, **kw) -> None:
    with JOBS_LOCK:
        JOBS[job_id].update(kw)


def _work(job_id: str, path: Path, profile: str | None) -> None:
    """Scan, triage, file. Each stage is reported so the UI can say where it is."""
    started = time.time()
    try:
        c = triage_client.TriageClient(cfg("CLOUDSEC_TRIAGE_URL",
                                           "http://127.0.0.1:8100"))
        health = c.health()
        _set(job_id, stage="scanning")
        file = triage_client.IaCFile(path=path.name, content=path.read_text())
        from cloudsec.scan import scan_file
        findings = scan_file(file, profile)

        _set(job_id, stage="triaging", findings=len(findings))
        result = triage_client.triage(file, findings, c)

        items = [{
            "tool": t.finding.tool,
            "check_id": t.finding.check_id,
            "occurrence": t.verdict.occurrence if t.verdict else 0,
            "severity": t.finding.severity,
            "title": t.finding.title,
            "start_line": t.finding.start_line,
            "end_line": t.finding.end_line,
            "label": t.verdict.label if t.verdict else None,
            "verdict_severity": t.verdict.severity if t.verdict else None,
            "confidence": getattr(t.verdict, "confidence", None) if t.verdict else None,
            "fix": t.verdict.fix if t.verdict else None,
            "reason": t.verdict.reason if t.verdict else None,
        } for t in result.items]
        ctx = result.context
        seconds = round(time.time() - started, 1)

        run_id = None
        db = _db()
        collector = cfg("CLOUDSEC_COLLECTOR")
        if db is not None or collector:
            _set(job_id, stage="filing")
            run = runs_mod.build_run([result], profile=profile, service=health,
                                     seconds=seconds, source="upload")
            if db is not None:
                run.setdefault("run_id", uuid.uuid4().hex)
                run.setdefault("created_at", datetime.datetime.now(
                    datetime.timezone.utc).isoformat(timespec="seconds"))
                with _DB_LOCK:
                    run_id = run_store.save(db, run)
            else:
                run_id = runs_mod.post_run(collector, run)

        _set(job_id, stage="done", seconds=seconds, run_id=run_id,
             result={
                 "context": ({"iac_type": ctx.iac_type,
                              "cloud_provider": ctx.cloud_provider,
                              "environment": ctx.environment,
                              "purpose": ctx.purpose} if ctx else None),
                 "items": items,
                 "tp": sum(1 for i in items if i["label"] == "TP"),
                 "fp": sum(1 for i in items if i["label"] == "FP"),
                 "unaddressed": sum(1 for i in items if i["label"] is None),
                 "fingerprint": health.get("fingerprint"),
                 "model": health.get("model"),
             })
    except Exception as e:
        _set(job_id, stage="error", error=f"{type(e).__name__}: {e}",
             seconds=round(time.time() - started, 1))
    finally:
        try:
            path.unlink()
            path.parent.rmdir()
        except Exception:
            pass


_DB = None
_DB_LOCK = threading.Lock()


def _db():
    """Local run store (CLOUDSEC_DB). None means: use the collector URL, if any."""
    global _DB
    path = cfg("CLOUDSEC_DB")
    if not path:
        return None
    with _DB_LOCK:
        if _DB is None:
            _DB = run_store.connect(path)
    return _DB


app = FastAPI(title="cloudsec-dashboard")


@app.get("/")
def index():
    return FileResponse(HERE / "index.html")


@app.get("/review")
def review():
    """The review view. Kept alongside the original page, not replacing it."""
    return FileResponse(HERE / "review.html")


@app.get("/api/config")
def config():
    """What this dashboard is pointed at, so the page can show provenance."""
    out = {"profile": cfg("CLOUDSEC_PROFILE"),
           "triage_url": cfg("CLOUDSEC_TRIAGE_URL", "http://127.0.0.1:8100"),
           "collector": cfg("CLOUDSEC_COLLECTOR"), "db": cfg("CLOUDSEC_DB"), "service": None}
    try:
        out["service"] = triage_client.TriageClient(out["triage_url"]).health()
    except Exception as e:
        out["error"] = str(e)
    return out


@app.post("/api/scan")
async def scan(file: UploadFile):
    data = await file.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"{len(data)} bytes; limit {MAX_BYTES}")
    if not data.strip():
        raise HTTPException(400, "empty file")

    # Keep the original name: the scanners dispatch on extension.
    tmp = Path(tempfile.mkdtemp(prefix="cloudsec-"))
    path = tmp / (Path(file.filename or "input.tf").name)
    path.write_bytes(data)

    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {"id": job_id, "filename": path.name, "stage": "queued",
                        "started": time.time()}
    threading.Thread(target=_work, args=(job_id, path, cfg("CLOUDSEC_PROFILE")),
                     daemon=True).start()
    return {"job_id": job_id}


@app.get("/api/jobs/{job_id}")
def job(job_id: str):
    with JOBS_LOCK:
        j = JOBS.get(job_id)
    if j is None:
        raise HTTPException(404, "no such job")
    return j


@app.get("/api/service")
def service():
    """Live service state, so a long wait can say why it is long."""
    try:
        return triage_client.TriageClient(
            cfg("CLOUDSEC_TRIAGE_URL", "http://127.0.0.1:8100")).health()
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/runs")
def history(limit: int = 20):
    """Run history: local store if configured, otherwise proxy the collector."""
    db = _db()
    if db is not None:
        with _DB_LOCK:
            return {"runs": run_store.list_runs(db, limit=limit)}
    url = cfg("CLOUDSEC_COLLECTOR")
    if not url:
        return {"runs": [], "note": "no collector configured"}
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/runs?limit={limit}",
                                    timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return JSONResponse({"runs": [], "error": str(e)}, status_code=200)


@app.get("/api/runs/{run_id}")
def one_run(run_id: str):
    """One stored run, for the history drill-down."""
    db = _db()
    if db is not None:
        with _DB_LOCK:
            run = run_store.get_run(db, run_id)
        if run is None:
            raise HTTPException(404, "run not found")
        return run
    url = cfg("CLOUDSEC_COLLECTOR")
    if not url:
        raise HTTPException(404, "no collector configured")
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/runs/{run_id}",
                                    timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        raise HTTPException(502, str(e))


def main():
    import argparse

    import uvicorn

    p = argparse.ArgumentParser(prog="python -m cloudsec.web.app")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--profile")
    p.add_argument("--triage-url")
    p.add_argument("--collector", help="standalone collector URL (optional)")
    p.add_argument("--db", help="local SQLite run store, e.g. runs.db")
    a = p.parse_args()
    if a.profile:
        os.environ["CLOUDSEC_PROFILE"] = a.profile
    if a.triage_url:
        os.environ["CLOUDSEC_TRIAGE_URL"] = a.triage_url
    if a.collector:
        os.environ["CLOUDSEC_COLLECTOR"] = a.collector
    if a.db:
        os.environ["CLOUDSEC_DB"] = a.db
    uvicorn.run(app, host=a.host, port=a.port, workers=1)


if __name__ == "__main__":
    main()
