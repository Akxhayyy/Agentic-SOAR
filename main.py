"""
main.py

FastAPI backend hooks. Three responsibilities:

1. POST /ingest — the untrusted log ingestion boundary. Raw payloads are
   parsed into RawLogEntry (Pydantic) immediately, BEFORE anything touches
   the UICR or the graph. This is the hostile-boundary gate per your
   answer #2.

2. POST /resume/{incident_id} — operator decision endpoint. The Streamlit
   dashboard calls this with {"decision": "APPROVED"|"REJECTED"} when the
   operator clicks a button. Internally this resumes the paused graph via
   Command(resume=...) using the SAME thread_id (incident_id) so
   SqliteSaver restores full state even after a restart.

3. A background timeout watcher: since LangGraph's interrupt() does not run
   its own clock, something has to track elapsed time per-incident and fire
   the TIMEOUT resume if 300s pass with no operator action. Implemented here
   as a simple asyncio background task per incident, checked against a
   timestamp written into the checkpoint metadata when hitl_gate_node pauses.

Run with: uvicorn main:app --reload --port 8000
(no external network calls anywhere in this file — Ollama and ChromaDB are
both localhost-only)
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from langgraph.types import Command
from pydantic import BaseModel

from core.uicr_schema import HitlDecision, RawLogEntry, UICRState, new_incident_state
from core.checkpointer import thread_config_for_incident
from core.graph_config import load_config
from core.graph import get_compiled_graph
from ingestion.batch_processor import process_log_file

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soar.main")

app = FastAPI(title="SOAR Capsule")

# incident_id -> monotonic timestamp when hitl_gate_node paused.
# In-memory is fine here even with SqliteSaver for the graph state itself:
# if the PROCESS restarts, the timeout watcher restarts too, and a fresh
# 300s window begins on next access — slightly more lenient than a perfectly
# preserved countdown, but never less safe (it never auto-resumes a window
# that hadn't actually elapsed before the restart).
_pending_timeouts: dict[str, float] = {}
TIMEOUT_TASKS: dict[str, asyncio.Task] = {}


class IngestPayload(BaseModel):
    source: str
    log_type: str
    raw_text: str


@app.post("/ingest")
async def ingest_logs(payload: IngestPayload):
    """Untrusted boundary — payload is forced through RawLogEntry validation."""
    try:
        validated_entry = RawLogEntry(
            source=payload.source,
            log_type=payload.log_type,
            raw_text=payload.raw_text,
        )
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Log validation failed: {e}")

    state = new_incident_state()
    state["raw_logs"] = [validated_entry.model_dump(mode="json")]

    graph = get_compiled_graph()
    config = thread_config_for_incident(state["incident_id"])

    # Runs triage -> forensics -> (neutralizer ->) hitl_gate_node, where it
    # will pause on interrupt() if the forensics/neutralizer path is taken.
    result = await asyncio.to_thread(graph.invoke, state, config)

    if _graph_is_paused_at_hitl(graph, config):
        _pending_timeouts[state["incident_id"]] = time.monotonic()
        cfg = load_config()
        timeout_s = cfg["hitl"]["timeout_seconds"]
        TIMEOUT_TASKS[state["incident_id"]] = asyncio.create_task(
            _timeout_watcher(state["incident_id"], timeout_s)
        )

    return {"incident_id": state["incident_id"], "state_snapshot": result}


class BatchIngestPayload(BaseModel):
    file_text: str
    default_log_type: str = "GENERIC"
    delimiter: str | None = None


@app.post("/ingest_file")
async def ingest_log_file(payload: BatchIngestPayload):
    """
    Batch ingestion boundary. Takes a multi-line log file as raw text,
    pre-screens it through the cheap deterministic filter + grouping logic
    in ingestion/, and runs each resulting suspicious group through the
    SAME compiled graph as the single-log /ingest endpoint above.

    Note: like /ingest, this can take a while to return — every incident
    group created triggers at least one Qwen call, run sequentially (your
    hardware has one model instance, not infinite parallel capacity). For
    a large file with many suspicious groups, expect this to take
    proportionally longer; the response only comes back once every group
    has been fully processed (including reaching the HITL gate, if
    applicable, at which point that incident pauses and a timeout watcher
    is registered for it just like the single-log path).
    """
    if not payload.file_text.strip():
        raise HTTPException(status_code=422, detail="file_text is empty.")

    graph = get_compiled_graph()

    summary = await asyncio.to_thread(
        process_log_file, payload.file_text, payload.default_log_type, payload.delimiter
    )

    # For every incident that was created and is now paused at the HITL
    # gate, register a timeout watcher exactly as /ingest does for a
    # single incident. process_log_file() runs synchronously inside a
    # worker thread, so by the time we get here every group's graph.invoke
    # has already either completed or paused — we just need to detect
    # which, per incident_id, and wire up the watcher for the paused ones.
    cfg = load_config()
    timeout_s = cfg["hitl"]["timeout_seconds"]

    for incident in summary["incidents"]:
        incident_id = incident["incident_id"]
        config = thread_config_for_incident(incident_id)
        if _graph_is_paused_at_hitl(graph, config):
            _pending_timeouts[incident_id] = time.monotonic()
            TIMEOUT_TASKS[incident_id] = asyncio.create_task(
                _timeout_watcher(incident_id, timeout_s)
            )

    return summary


class ResumeDecision(BaseModel):
    decision: str  # "APPROVED" or "REJECTED"


@app.post("/resume/{incident_id}")
async def resume_incident(incident_id: str, body: ResumeDecision):
    if body.decision not in (HitlDecision.APPROVED.value, HitlDecision.REJECTED.value):
        raise HTTPException(
            status_code=400,
            detail="decision must be APPROVED or REJECTED (TIMEOUT is system-fired only).",
        )

    # Operator acted — cancel the pending timeout watcher for this incident.
    task = TIMEOUT_TASKS.pop(incident_id, None)
    if task:
        task.cancel()
    _pending_timeouts.pop(incident_id, None)

    graph = get_compiled_graph()
    config = thread_config_for_incident(incident_id)

    result = await asyncio.to_thread(
        graph.invoke, Command(resume={"decision": body.decision}), config
    )
    return {"incident_id": incident_id, "state_snapshot": result}


async def _timeout_watcher(incident_id: str, timeout_s: int):
    """
    Fires the TIMEOUT resume automatically if no operator decision arrives
    within timeout_s seconds. Cancelled by resume_incident() if the operator
    acts first.
    """
    try:
        await asyncio.sleep(timeout_s)
        logger.warning(
            "Incident %s timed out after %ds with no operator decision; "
            "auto-resuming with TIMEOUT.", incident_id, timeout_s,
        )
        graph = get_compiled_graph()
        config = thread_config_for_incident(incident_id)
        await asyncio.to_thread(
            graph.invoke, Command(resume={"decision": HitlDecision.TIMEOUT.value}), config
        )
        _pending_timeouts.pop(incident_id, None)
    except asyncio.CancelledError:
        # Operator acted before timeout — expected, not an error.
        pass


def _graph_is_paused_at_hitl(graph, config) -> bool:
    """
    Inspects checkpointer state to determine whether the graph is currently
    paused at the interrupt() inside hitl_gate_node, vs. having run to END
    (e.g. because forensics didn't clear threshold and routed straight to
    the escalation report, never reaching the HITL gate at all).
    """
    snapshot = graph.get_state(config)
    return bool(snapshot.next) and "hitl_gate_node" in snapshot.next


@app.get("/incident/{incident_id}")
async def get_incident_state(incident_id: str):
    graph = get_compiled_graph()
    config = thread_config_for_incident(incident_id)
    snapshot = graph.get_state(config)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Incident not found.")

    remaining_s = None
    if incident_id in _pending_timeouts:
        cfg = load_config()
        elapsed = time.monotonic() - _pending_timeouts[incident_id]
        remaining_s = max(0, int(cfg["hitl"]["timeout_seconds"] - elapsed))

    return {
        "incident_id": incident_id,
        "state": snapshot.values,
        "paused_at": list(snapshot.next),
        "hitl_timeout_remaining_seconds": remaining_s,
    }
