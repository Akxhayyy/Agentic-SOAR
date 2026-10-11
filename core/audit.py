"""
core/audit.py

Append-only JSONL audit trail at config logging.audit_log_path. One line
per security-relevant event: ingest, HITL decision (with actor + note),
timeout, rollback. Writes are serialised with a lock; reads tail the file.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from core.graph_config import load_config

_lock = threading.Lock()


def _path() -> Path:
    p = Path(load_config()["logging"]["audit_log_path"])
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def audit(event: str, incident_id: str | None = None, actor: str = "system", **fields) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "incident_id": incident_id,
        "actor": actor,
        **fields,
    }
    line = json.dumps(record, default=str)
    with _lock, open(_path(), "a", encoding="utf-8") as f:
        f.write(line + "\n")


def tail(limit: int = 100, incident_id: str | None = None) -> list[dict]:
    p = _path()
    if not p.exists():
        return []
    out: deque = deque(maxlen=limit)
    with _lock, open(p, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if incident_id is None or rec.get("incident_id") == incident_id:
                out.append(rec)
    return list(reversed(out))
