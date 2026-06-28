"""
core/checkpointer.py

Swaps LangGraph's default in-memory MemorySaver for SqliteSaver, persisted
at config.hitl.checkpointer_db_path. This is the upgrade you specified:
if the workstation reboots mid-HITL-window, the graph can resume from the
last checkpoint on next boot instead of losing the incident.

Two things matter here that are easy to get wrong:

1. The DB directory must exist BEFORE sqlite3.connect() is called, or you
   get a silent "unable to open database file" error. We create it
   defensively on import.

2. check_same_thread=False is required because Streamlit and FastAPI may
   each touch the checkpointer from different threads. SqliteSaver itself
   is not inherently thread-safe for concurrent WRITES, so the calling
   code must still serialize writes per-incident (each incident_id is its
   own thread/config namespace via LangGraph's `configurable.thread_id`,
   which keeps incidents from colliding with each other even though the
   underlying file handle is shared).
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver

from core.graph_config import load_config


def get_checkpointer() -> SqliteSaver:
    cfg = load_config()
    db_path = Path(cfg["hitl"]["checkpointer_db_path"])
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Set connection timeout to 30s to prevent locks on concurrent operations
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30.0)
    # Enable WAL mode for high concurrency read/write isolation
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return SqliteSaver(conn)


def thread_config_for_incident(incident_id: str) -> dict:
    """
    LangGraph keys checkpoints by `configurable.thread_id`. Using the
    incident_id directly as the thread_id means resuming after a reboot
    is just: invoke the graph again with this same config dict, and
    LangGraph will pick up exactly where the interrupt() call paused it.
    """
    return {"configurable": {"thread_id": incident_id}}
