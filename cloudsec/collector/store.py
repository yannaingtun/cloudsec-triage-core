"""SQLite store for triage runs.

One file, WAL mode, no server. A run is immutable once stored: re-posting a
run_id is rejected rather than silently overwritten, because a retried CI job
is a new run that shares an external_ref, not a rewrite of history.

Findings and verdicts share a table. The pipeline guarantees exactly one
verdict per finding, so separate tables would buy nothing and would let the
two drift apart. label is NULL when the model never addressed the finding,
which is a real outcome and must not be confused with FP.

Scanner versions and the model fingerprint are stored on every run. Findings
are not interpretable without the first, and verdicts are not attributable
without the second. all_evals.csv has neither, which is why no older run's
provenance can be recovered.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id            TEXT PRIMARY KEY,
    created_at        TEXT NOT NULL,
    source            TEXT NOT NULL,
    external_ref      TEXT,
    project           TEXT,
    branch            TEXT,
    commit_sha        TEXT,
    profile           TEXT,
    checkov_version   TEXT,
    trivy_version     TEXT,
    model             TEXT,
    model_fingerprint TEXT,
    transformers      TEXT,
    seconds           REAL,
    client            TEXT
);
CREATE INDEX IF NOT EXISTS runs_created  ON runs(created_at);
CREATE INDEX IF NOT EXISTS runs_external ON runs(external_ref);
CREATE INDEX IF NOT EXISTS runs_project  ON runs(project, branch);

CREATE TABLE IF NOT EXISTS files (
    file_id        INTEGER PRIMARY KEY,
    run_id         TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    path           TEXT NOT NULL,
    content_sha256 TEXT,
    iac_type       TEXT,
    cloud_provider TEXT,
    environment    TEXT,
    purpose        TEXT,
    raw_output     TEXT
);
CREATE INDEX IF NOT EXISTS files_run ON files(run_id);
CREATE INDEX IF NOT EXISTS files_sha ON files(content_sha256);

CREATE TABLE IF NOT EXISTS findings (
    finding_id       INTEGER PRIMARY KEY,
    file_id          INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    idx              INTEGER NOT NULL,
    tool             TEXT NOT NULL,
    check_id         TEXT NOT NULL,
    occurrence       INTEGER NOT NULL,
    severity         TEXT,
    title            TEXT,
    start_line       INTEGER,
    end_line         INTEGER,
    label            TEXT,
    verdict_severity TEXT,
    fix              TEXT,
    reason           TEXT,
    confidence       REAL,
    confidence_source TEXT
);
CREATE INDEX IF NOT EXISTS findings_file  ON findings(file_id);
CREATE INDEX IF NOT EXISTS findings_check ON findings(check_id);
"""

RUN_COLS = ("run_id", "created_at", "source", "external_ref", "project",
            "branch", "commit_sha", "profile", "checkov_version",
            "trivy_version", "model", "model_fingerprint", "transformers",
            "seconds", "client")


class DuplicateRun(Exception):
    """A run with this id is already stored."""


def connect(path: str | Path) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL survives an unclean shutdown far better than the rollback journal,
    # which matters on a machine that has already lost power once.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    # Existing databases predate these columns; CREATE TABLE IF NOT EXISTS
    # will not add them. NULL is correct for old rows: not measured, which is
    # different from measured as uncertain.
    have = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    for col, typ in (("confidence", "REAL"), ("confidence_source", "TEXT")):
        if col not in have:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {typ}")
    conn.commit()
    return conn


def save(conn: sqlite3.Connection, run: dict) -> str:
    """Store one run atomically. Raises DuplicateRun if the id exists."""
    rid = run["run_id"]
    with conn:  # one transaction; a partial run is worse than no run
        if conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (rid,)).fetchone():
            raise DuplicateRun(rid)
        conn.execute(
            f"INSERT INTO runs ({','.join(RUN_COLS)}) "
            f"VALUES ({','.join('?' * len(RUN_COLS))})",
            tuple(run.get(c) for c in RUN_COLS))

        for f in run.get("files", []):
            ctx = f.get("context") or {}
            cur = conn.execute(
                "INSERT INTO files (run_id, path, content_sha256, iac_type, "
                "cloud_provider, environment, purpose, raw_output) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (rid, f.get("path"), f.get("content_sha256"),
                 ctx.get("iac_type"), ctx.get("cloud_provider"),
                 ctx.get("environment"), ctx.get("purpose"),
                 f.get("raw_output")))
            fid = cur.lastrowid
            conn.executemany(
                "INSERT INTO findings (file_id, idx, tool, check_id, occurrence, "
                "severity, title, start_line, end_line, label, verdict_severity, "
                "fix, reason, confidence, confidence_source) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(fid, i, x.get("tool"), x.get("check_id"), x.get("occurrence", 0),
                  x.get("severity"), x.get("title"), x.get("start_line"),
                  x.get("end_line"), x.get("label"), x.get("verdict_severity"),
                  x.get("fix"), x.get("reason"), x.get("confidence"),
                  x.get("confidence_source"))
                 for i, x in enumerate(f.get("findings", []))])
    return rid


def list_runs(conn, limit=50, project=None, external_ref=None) -> list[dict]:
    where, args = [], []
    if project:
        where.append("project = ?"); args.append(project)
    if external_ref:
        where.append("external_ref = ?"); args.append(external_ref)
    sql = ("SELECT r.*, "
           "(SELECT COUNT(*) FROM files f WHERE f.run_id = r.run_id) AS files, "
           "(SELECT COUNT(*) FROM findings n JOIN files f ON n.file_id = f.file_id "
           " WHERE f.run_id = r.run_id) AS findings, "
           "(SELECT COUNT(*) FROM findings n JOIN files f ON n.file_id = f.file_id "
           " WHERE f.run_id = r.run_id AND n.label = 'TP') AS tp, "
           "(SELECT COUNT(*) FROM findings n JOIN files f ON n.file_id = f.file_id "
           " WHERE f.run_id = r.run_id AND n.label IS NULL) AS unaddressed "
           "FROM runs r")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in conn.execute(sql, args)]


def get_run(conn, run_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        return None
    run = dict(row)
    run["files"] = []
    for f in conn.execute("SELECT * FROM files WHERE run_id = ? ORDER BY file_id",
                          (run_id,)):
        d = dict(f)
        d["findings"] = [dict(x) for x in conn.execute(
            "SELECT * FROM findings WHERE file_id = ? ORDER BY idx",
            (d["file_id"],))]
        run["files"].append(d)
    return run
