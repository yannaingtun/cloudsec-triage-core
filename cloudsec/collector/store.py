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
    raw_output     TEXT,
    content        TEXT   -- the file as scanned; see the retention note
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

/* A human's judgement, kept apart from the model's. Overwriting the verdict
   would destroy the only thing that makes this worth collecting: the
   agreement rate between model and reviewer, and a stream of corrections.
   Rows accumulate; the highest review_id for a finding is the current one. */
CREATE TABLE IF NOT EXISTS reviews (
    review_id  INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    reviewer   TEXT,
    decision   TEXT NOT NULL,
    label      TEXT,
    note       TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reviews_finding ON reviews(finding_id);

/* The resolved verdict: the human's if one exists, otherwise the model's.
   A view rather than a stored column, so the two can never drift apart and
   it is always clear which source a verdict came from. */
CREATE VIEW IF NOT EXISTS verdicts AS
SELECT
    f.*,
    fi.run_id,
    fi.path,
    r.decision   AS review_decision,
    r.label      AS review_label,
    r.reviewer   AS reviewer,
    r.note       AS review_note,
    r.created_at AS reviewed_at,
    CASE
        WHEN r.decision = 'override' THEN r.label
        ELSE f.label
    END AS final_label,
    CASE
        WHEN r.review_id IS NULL THEN 'model'
        WHEN r.decision = 'agree' THEN 'model, confirmed'
        ELSE 'human'
    END AS verdict_source
FROM findings f
JOIN files fi ON fi.file_id = f.file_id
LEFT JOIN (
    SELECT r1.* FROM reviews r1
    JOIN (SELECT finding_id, MAX(review_id) AS mx FROM reviews GROUP BY finding_id) m
      ON r1.review_id = m.mx
) r ON r.finding_id = f.finding_id;
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
    have_f = {r[1] for r in conn.execute("PRAGMA table_info(files)")}
    if "content" not in have_f:
        conn.execute("ALTER TABLE files ADD COLUMN content TEXT")
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
                "cloud_provider, environment, purpose, raw_output, content) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (rid, f.get("path"), f.get("content_sha256"),
                 ctx.get("iac_type"), ctx.get("cloud_provider"),
                 ctx.get("environment"), ctx.get("purpose"),
                 f.get("raw_output"), f.get("content")))
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


def add_review(conn, finding_id: int, decision: str, label: str | None = None,
               reviewer: str | None = None, note: str | None = None) -> dict:
    """Record one judgement. Never updates in place."""
    from datetime import datetime, timezone

    if decision not in ("agree", "override"):
        raise ValueError(f"decision must be agree or override, not {decision!r}")
    if decision == "override" and label not in ("TP", "FP"):
        raise ValueError("an override needs a label of TP or FP")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with conn:
        if not conn.execute("SELECT 1 FROM findings WHERE finding_id = ?",
                            (finding_id,)).fetchone():
            raise KeyError(finding_id)
        cur = conn.execute(
            "INSERT INTO reviews (finding_id, reviewer, decision, label, note, "
            "created_at) VALUES (?,?,?,?,?,?)",
            (finding_id, reviewer, decision, label, note, now))
    return {"review_id": cur.lastrowid, "finding_id": finding_id,
            "decision": decision, "label": label, "reviewer": reviewer,
            "note": note, "created_at": now}


def latest_reviews(conn, run_id: str) -> dict[int, dict]:
    """The current judgement per finding in a run, if any."""
    sql = ("SELECT r.* FROM reviews r "
           "JOIN (SELECT finding_id, MAX(review_id) AS mx FROM reviews "
           "      GROUP BY finding_id) m ON r.review_id = m.mx "
           "JOIN findings f ON f.finding_id = r.finding_id "
           "JOIN files fi ON fi.file_id = f.file_id WHERE fi.run_id = ?")
    return {r["finding_id"]: dict(r) for r in conn.execute(sql, (run_id,))}


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
    reviews = latest_reviews(conn, run_id)
    run["files"] = []
    for f in conn.execute("SELECT * FROM files WHERE run_id = ? ORDER BY file_id",
                          (run_id,)):
        d = dict(f)
        d["findings"] = [dict(x) for x in conn.execute(
            "SELECT * FROM findings WHERE file_id = ? ORDER BY idx",
            (d["file_id"],))]
        for x in d["findings"]:
            rv = reviews.get(x["finding_id"])
            x["review"] = rv
            # Same rule as the verdicts view, so API and SQL agree.
            x["final_label"] = (rv["label"] if rv and rv["decision"] == "override"
                                else x["label"])
            x["verdict_source"] = ("model" if not rv else
                                   "model, confirmed" if rv["decision"] == "agree"
                                   else "human")
        run["files"].append(d)
    return run
