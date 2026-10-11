"""
core/graph.py

Wires the 4-agent pipeline into a LangGraph StateGraph.

Node sequence:
  triage -> forensics -> [route_after_forensics]
    -> cleared:      neutralizer -> [route_after_neutralizer]
                       -> ok:    hitl_arm -> hitl_gate_node -> [route_after_hitl]
                                   -> APPROVED: execute_action -> uicr_compress
                                   -> REJECTED / TIMEOUT:         uicr_compress
                       -> error: uicr_compress
    -> not cleared / error: uicr_compress
  uicr_compress -> generate_report -> END

Conditional edges are small pure functions so the decision logic is
auditable without reading node internals:
  - route_after_forensics(): the ONLY place the 0.70 hard threshold is acted on.
  - route_after_hitl(): the ONLY place hitl_decision branches.

hitl_arm exists because LangGraph discards a node's partial state updates
when interrupt() raises: anything hitl_gate_node wrote before pausing was
lost, so the checkpoint showed NEUTRALIZER_PLANNED (not AWAITING_HITL) and
carried no pause timestamp. hitl_arm commits both in its own checkpoint,
then hitl_gate_node pauses. On resume, hitl_gate_node re-runs from the top
and interrupt() returns the operator's Command(resume=...) payload.

Every node is wrapped by _instrument(): it records real per-node timings
into state["phase_history"], publishes live events for the UI, and turns
an unexpected exception (e.g. Ollama down) into state["error"] +
current_phase=FAILED instead of an HTTP 500 with a half-written incident.
Subsequent agent nodes are skipped; compress + report still run so every
incident ends with an audit record.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Callable

from langgraph.errors import GraphBubbleUp
from langgraph.graph import StateGraph, END
from langgraph.types import interrupt

from core import events
from core.uicr_schema import HitlDecision, PipelinePhase, UICRState
from core.checkpointer import get_checkpointer
from core.graph_config import load_config
from agents.triage import triage_node
from agents.forensics import forensics_node
from agents.neutralizer import neutralizer_node
from agents.responder import uicr_compress, generate_report
from execution.wrapper import execute_action

logger = logging.getLogger("soar.graph")

# Nodes that must still run after a failure, so the incident gets a report.
_ALWAYS_RUN = {"uicr_compress", "generate_report"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _instrument(name: str, fn: Callable[[UICRState], UICRState]) -> Callable[[UICRState], UICRState]:
    def wrapper(state: UICRState) -> UICRState:
        incident_id = state.get("incident_id")
        if state.get("error") and name not in _ALWAYS_RUN:
            return state

        started_at = _now()
        t0 = time.perf_counter()
        events.publish("node_started", incident_id=incident_id, node=name)
        try:
            state = fn(state)
        except GraphBubbleUp:
            raise  # interrupt() control flow — never swallow
        except Exception as e:  # noqa: BLE001 — convert to a recorded failure
            logger.exception("Node %s failed for incident %s", name, incident_id)
            state["error"] = f"{name}: {type(e).__name__}: {e}"[:500]
            state["current_phase"] = PipelinePhase.FAILED.value

        duration = round(time.perf_counter() - t0, 3)
        if name == "hitl_gate_node" and state.get("hitl_paused_at"):
            # Measure the human wait, not the instant resume re-run.
            started_at = state["hitl_paused_at"]
            duration = round(
                (datetime.now(timezone.utc) - datetime.fromisoformat(started_at)).total_seconds(), 3
            )
        state["phase_history"] = list(state.get("phase_history") or []) + [{
            "node": name,
            "phase": state.get("current_phase"),
            "started_at": started_at,
            "ended_at": _now(),
            "duration_s": duration,
        }]
        events.publish(
            "node_finished",
            incident_id=incident_id,
            node=name,
            phase=state.get("current_phase"),
            threat_status=state.get("threat_status"),
            duration_s=duration,
            error=state.get("error"),
        )
        return state

    wrapper.__name__ = name
    return wrapper


def hitl_arm(state: UICRState) -> UICRState:
    """Commits the AWAITING_HITL phase + pause timestamp before the interrupt."""
    state["current_phase"] = PipelinePhase.AWAITING_HITL.value
    state["hitl_paused_at"] = _now()
    events.publish(
        "hitl_waiting",
        incident_id=state.get("incident_id"),
        timeout_seconds=load_config()["hitl"]["timeout_seconds"],
    )
    return state


def hitl_gate_node(state: UICRState) -> UICRState:
    """
    The Human-in-the-Loop Interrupt Gate.

    interrupt() pauses the graph and persists state via the checkpointer.
    The caller (main.py) detects the pause via graph.get_state().next,
    runs the timeout watcher, and resumes with
    Command(resume={"decision": APPROVED|REJECTED|TIMEOUT, "note": str}).
    """
    operator_input = interrupt(
        {
            "incident_id": state["incident_id"],
            "action_plan": state["action_plan"],
            "forensics_summary": (state.get("forensics") or {}).get("rag_timeline_notes"),
            "timeout_seconds": load_config()["hitl"]["timeout_seconds"],
        }
    )
    decision = (operator_input or {}).get("decision", HitlDecision.TIMEOUT.value)
    if decision not in {d.value for d in HitlDecision} or decision == HitlDecision.PENDING.value:
        decision = HitlDecision.TIMEOUT.value
    state["hitl_decision"] = decision
    note = (operator_input or {}).get("note")
    state["hitl_operator_note"] = str(note)[:500] if note else None
    return state


def route_after_forensics(state: UICRState) -> str:
    """The ONLY place the hard 0.70 threshold decision is acted on."""
    if state.get("error"):
        return "uicr_compress"
    forensics = state.get("forensics") or {}
    if forensics.get("cleared_threshold") is True:
        return "neutralizer"
    return "uicr_compress"  # bypass neutralizer entirely -> escalation report


def route_after_neutralizer(state: UICRState) -> str:
    return "uicr_compress" if state.get("error") else "hitl_arm"


def route_after_hitl(state: UICRState) -> str:
    """The ONLY place hitl_decision branches the graph."""
    if state.get("hitl_decision") == HitlDecision.APPROVED.value:
        return "execute_action"
    # REJECTED and TIMEOUT both skip the execution wrapper entirely.
    return "uicr_compress"


NODES: dict[str, Callable[[UICRState], UICRState]] = {
    "triage": triage_node,
    "forensics": forensics_node,
    "neutralizer": neutralizer_node,
    "hitl_arm": hitl_arm,
    "hitl_gate_node": hitl_gate_node,
    "execute_action": execute_action,
    "uicr_compress": uicr_compress,
    "generate_report": generate_report,
}


def build_graph(checkpointer=None):
    graph = StateGraph(UICRState)
    for name, fn in NODES.items():
        graph.add_node(name, _instrument(name, fn))

    graph.set_entry_point("triage")
    graph.add_edge("triage", "forensics")
    graph.add_conditional_edges(
        "forensics", route_after_forensics,
        {"neutralizer": "neutralizer", "uicr_compress": "uicr_compress"},
    )
    graph.add_conditional_edges(
        "neutralizer", route_after_neutralizer,
        {"hitl_arm": "hitl_arm", "uicr_compress": "uicr_compress"},
    )
    graph.add_edge("hitl_arm", "hitl_gate_node")
    graph.add_conditional_edges(
        "hitl_gate_node", route_after_hitl,
        {"execute_action": "execute_action", "uicr_compress": "uicr_compress"},
    )
    graph.add_edge("execute_action", "uicr_compress")
    graph.add_edge("uicr_compress", "generate_report")
    graph.add_edge("generate_report", END)

    return graph.compile(checkpointer=checkpointer or get_checkpointer())


# Module-level compiled graph, built once per process.
compiled_graph = None


def get_compiled_graph():
    global compiled_graph
    if compiled_graph is None:
        compiled_graph = build_graph()
    return compiled_graph
