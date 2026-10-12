"""
ingestion/log_store.py

Append-only SQLite store of EVERY parsed log line (suspicious or benign),
written at ingest time. It exists so the forensics agent's
get_related_logs tool can look beyond the incident's own lines — e.g. "what
else did 10.0.0.99 do in the 5 minutes around this burst?" — which the
cheap filter would otherwise have thrown away.

Read-only for agents: the only writer is ingestion (add_lines).
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

from core.graph_config import load_config
from ingestion.cheap_filter import ParsedLogLine

_lock = threading.Lock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS log_lines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    ts TEXT,
    ip TEXT,
    user TEXT,
    log_type TEXT,
    suspicious INTEGER NOT NULL,
    reason TEXT,
    raw_text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_ip ON log_lines(ip);
CREATE INDEX IF NOT EXISTS idx_log_user ON log_lines(user);
CREATE INDEX IF NOT EXISTS idx_log_ts ON log_lines(ts);
"""


def _connect() -> sqlite3.Connection:
    path = Path(load_config()["forensics"]["log_store_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.executescript(_SCHEMA)
    return conn


def add_lines(batch_id: str, lines: list[ParsedLogLine]) -> int:
    rows = [
        (batch_id, l.timestamp.isoformat() if l.timestamp else None, l.extracted_ip, l.extracted_user,
         l.log_type, int(l.is_suspicious), l.match_reason, l.raw_text[:1024])
        for l in lines
    ]
    with _lock:
        conn = _connect()
        try:
            conn.executemany(
                "INSERT INTO log_lines (batch_id, ts, ip, user, log_type, suspicious, reason, raw_text) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows,
            )
            conn.commit()
        finally:
            conn.close()
    return len(rows)


def related_lines(indicator: str, first_seen: str | None, last_seen: str | None,
                  window_s: int, limit: int = 200) -> list[dict]:
    """
    Lines mentioning `indicator` (exact ip/user match, or substring of the
    text) within [first_seen - window, last_seen + window]. If the incident
    has no timestamps, the time filter is skipped.
    """
    like = "%" + indicator.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sql = ("SELECT ts, ip, user, log_type, suspicious, reason, raw_text, batch_id FROM log_lines "
           "WHERE (ip = ? OR user = ? OR raw_text LIKE ? ESCAPE '\\')")
    params: list = [indicator, indicator, like]
    if first_seen and last_seen:
        lo = (datetime.fromisoformat(first_seen) - timedelta(seconds=window_s)).isoformat()
        hi = (datetime.fromisoformat(last_seen) + timedelta(seconds=window_s)).isoformat()
        sql += " AND ts IS NOT NULL AND ts >= ? AND ts <= ?"
        params += [lo, hi]
    sql += " ORDER BY ts LIMIT ?"
    params.append(limit)
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
    keys = ("ts", "ip", "user", "log_type", "suspicious", "reason", "raw_text", "batch_id")
    return [dict(zip(keys, r)) for r in rows]
