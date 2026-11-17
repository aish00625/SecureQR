"""SQLite persistence for scan history.

All queries use parameter binding (``?`` placeholders) - user input is never
concatenated into SQL, which prevents SQL injection.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       TEXT    NOT NULL,
    source           TEXT    NOT NULL CHECK (source IN ('upload', 'webcam', 'url')),
    content_type     TEXT    NOT NULL,
    raw_content      TEXT    NOT NULL,
    url              TEXT,
    host             TEXT,
    ml_label         TEXT,
    ml_probability   REAL,
    heuristic_score  INTEGER,
    risk_level       TEXT    NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    result_json      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_level);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        path = current_app.config["DATABASE"]
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app) -> None:
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()
    app.teardown_appcontext(close_db)


def insert_scan(source: str, result: dict) -> int:
    ml = result.get("ml") or {}
    heur = result.get("heuristics") or {}
    db = get_db()
    cur = db.execute(
        """INSERT INTO scans (created_at, source, content_type, raw_content, url, host,
                              ml_label, ml_probability, heuristic_score, risk_level, result_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            source,
            result["content_type"],
            result["raw_content"][:4096],
            (result.get("url") or None),
            (heur.get("facts") or {}).get("host"),
            ml.get("label") if ml.get("available") else None,
            ml.get("phishing_probability") if ml.get("available") else None,
            heur.get("score"),
            result["risk_level"],
            json.dumps(result),
        ),
    )
    db.commit()
    return int(cur.lastrowid)


def _row_summary(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in ("id", "created_at", "source", "content_type", "raw_content", "url",
                                "host", "ml_label", "ml_probability", "heuristic_score", "risk_level")}


def list_scans(limit: int = 25, offset: int = 0, risk: str | None = None,
               query: str | None = None) -> tuple[list[dict], int]:
    where, params = [], []
    if risk in {"LOW", "MEDIUM", "HIGH"}:
        where.append("risk_level = ?")
        params.append(risk)
    if query:
        where.append("(raw_content LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\')")
        like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params += [like, like]
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM scans {clause}", params).fetchone()[0]
    rows = db.execute(f"SELECT * FROM scans {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                      params + [limit, offset]).fetchall()
    return [_row_summary(r) for r in rows], int(total)


def get_scan(scan_id: int) -> dict | None:
    row = get_db().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    out = _row_summary(row)
    out["result"] = json.loads(row["result_json"])
    return out


def delete_scan(scan_id: int) -> bool:
    db = get_db()
    cur = db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    db.commit()
    return cur.rowcount > 0


def clear_scans() -> int:
    db = get_db()
    cur = db.execute("DELETE FROM scans")
    db.commit()
    return cur.rowcount


def stats(days: int = 14) -> dict:
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    by_risk = {r["risk_level"]: r["n"] for r in db.execute(
        "SELECT risk_level, COUNT(*) AS n FROM scans GROUP BY risk_level")}
    by_source = {r["source"]: r["n"] for r in db.execute(
        "SELECT source, COUNT(*) AS n FROM scans GROUP BY source")}
    by_type = {r["content_type"]: r["n"] for r in db.execute(
        "SELECT content_type, COUNT(*) AS n FROM scans GROUP BY content_type")}
    ml = {r["ml_label"]: r["n"] for r in db.execute(
        "SELECT ml_label, COUNT(*) AS n FROM scans WHERE ml_label IS NOT NULL GROUP BY ml_label")}

    start = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date()
    daily_rows = db.execute(
        """SELECT substr(created_at, 1, 10) AS day, risk_level, COUNT(*) AS n FROM scans
           WHERE substr(created_at, 1, 10) >= ? GROUP BY day, risk_level""",
        (start.isoformat(),)).fetchall()
    daily = {(start + timedelta(days=i)).isoformat(): {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
             for i in range(days)}
    for r in daily_rows:
        if r["day"] in daily:
            daily[r["day"]][r["risk_level"]] = r["n"]

    flag_counts: dict[str, dict] = {}
    for (rj,) in db.execute("SELECT result_json FROM scans ORDER BY id DESC LIMIT 1000"):
        for f in ((json.loads(rj).get("heuristics") or {}).get("findings") or []):
            e = flag_counts.setdefault(f["id"], {"id": f["id"], "title": f["title"], "count": 0})
            e["count"] += 1
    top_flags = sorted(flag_counts.values(), key=lambda e: -e["count"])[:8]

    hosts = [dict(host=r["host"], count=r["n"], max_risk=r["mr"]) for r in db.execute(
        """SELECT host, COUNT(*) AS n,
                  MAX(CASE risk_level WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS mr
           FROM scans WHERE host IS NOT NULL AND host != '' GROUP BY host ORDER BY n DESC LIMIT 8""")]
    for h in hosts:
        h["max_risk"] = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}[h["max_risk"]]

    return {"total": total,
            "by_risk": {k: by_risk.get(k, 0) for k in ("LOW", "MEDIUM", "HIGH")},
            "by_source": {k: by_source.get(k, 0) for k in ("upload", "webcam", "url")},
            "by_content_type": by_type, "ml_labels": ml,
            "daily": [{"day": d, **v} for d, v in daily.items()],
            "top_findings": top_flags, "top_hosts": hosts}
