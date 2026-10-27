"""Run history. Separate from the model service on purpose.

The model service holds 16 GB of weights and takes 90 seconds to start. This
holds a SQLite file and starts instantly. Keeping them apart means a schema
change does not cost a model reload, and a locked database cannot stall
inference.

Clients post a run after rendering their own report, so this is never on the
path to getting a result. If it is down the scan still works and only the
record is lost, which is the right way round.

    python -m cloudsec.collector.app --db ~/Documents/cloudsec-data/runs.db
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from cloudsec.collector import store

STATE: dict = {}


class FindingIn(BaseModel):
    tool: str
    check_id: str
    occurrence: int = 0
    severity: str | None = None
    title: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    label: str | None = None
    verdict_severity: str | None = None
    fix: str | None = None
    reason: str | None = None
    confidence: float | None = None       # P(TP), not P(chosen)
    confidence_source: str | None = None  # 'logprob' or 'stated'


class ContextIn(BaseModel):
    iac_type: str | None = None
    cloud_provider: str | None = None
    environment: str | None = None
    purpose: str | None = None


class FileIn(BaseModel):
    path: str
    content_sha256: str | None = None
    context: ContextIn | None = None
    raw_output: str | None = None
    findings: list[FindingIn] = Field(default_factory=list)


class RunIn(BaseModel):
    run_id: str
    created_at: str
    source: str
    external_ref: str | None = None
    project: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    profile: str | None = None
    checkov_version: str | None = None
    trivy_version: str | None = None
    model: str | None = None
    model_fingerprint: str | None = None
    transformers: str | None = None
    seconds: float | None = None
    client: str | None = None
    files: list[FileIn] = Field(default_factory=list)


@asynccontextmanager
async def lifespan(app: FastAPI):
    path = os.environ.get("CLOUDSEC_DB")
    if not path:
        raise RuntimeError("set CLOUDSEC_DB to the sqlite file")
    STATE["db"] = store.connect(path)
    STATE["path"] = path
    print(f"collector ready: {path}")
    yield
    STATE["db"].close()
    STATE.clear()


app = FastAPI(title="cloudsec-collector", lifespan=lifespan)


@app.get("/health")
def health():
    n = STATE["db"].execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
    return {"db": STATE["path"], "runs": n}


@app.post("/runs", status_code=201)
def post_run(r: RunIn):
    data = r.model_dump() if hasattr(r, "model_dump") else r.dict()
    try:
        rid = store.save(STATE["db"], data)
    except store.DuplicateRun:
        raise HTTPException(409, f"run {r.run_id} already stored")
    return {"run_id": rid, "stored": True}


@app.get("/runs")
def get_runs(limit: int = Query(50, le=500), project: str | None = None,
             external_ref: str | None = None):
    return {"runs": store.list_runs(STATE["db"], limit, project, external_ref)}


@app.get("/runs/{run_id}")
def get_one(run_id: str):
    run = store.get_run(STATE["db"], run_id)
    if run is None:
        raise HTTPException(404, f"no run {run_id}")
    return run


def main():
    import argparse

    import uvicorn

    p = argparse.ArgumentParser(prog="python -m cloudsec.collector.app")
    p.add_argument("--db", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8110)
    a = p.parse_args()
    os.environ["CLOUDSEC_DB"] = os.path.expanduser(a.db)
    uvicorn.run(app, host=a.host, port=a.port, workers=1)


if __name__ == "__main__":
    main()
