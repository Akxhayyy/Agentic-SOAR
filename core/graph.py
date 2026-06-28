"""
core/graph.py

Wires the 4-agent pipeline into a LangGraph StateGraph.

Node sequence:
  triage -> forensics -> [conditional: cleared_threshold?]
    -> True:  neutralizer -> hitl_gate -> [conditional: hitl_decision?]
         -> APPROVED: execute_action -> uicr_compress -> generate_report -> END
         -> REJECTED: uicr_compress -> generate_report -> END  (skips wrapper, threat OPEN)
         -> TIMEOUT:  uicr_compress -> generate_report -> END  (skips wrapper, ESCALATED)
    -> False: uicr_compress -> generate_report -> END  (escalation report, bypasses Neutralizer)

Two distinct conditional edges, both kept as small pure functions so the
decision logic is auditable without reading node internals:
  - route_after_forensics(): the ONLY place the 0.70 hard threshold is acted on.
  - route_after_hitl(): the ONLY place hitl_decision branches.

The HITL gate itself (hitl_gate_node) calls LangGraph's interrupt() to pause
execution. Resuming happens externally (FastAPI endpoint / Streamlit action)
by re-invoking the graph with a Command(resume=...) carrying the operator's
decision, using the SAME thread_config (incident_id) so SqliteSaver can
restore full prior state even across a process restart.
"""

from __future__ import annotations

import logging

from langgraph.graph import StateGraph, END
from langgraph.types import interrupt

from core.uicr_schema import HitlDecision, PipelinePhase, UICRState
from core.checkpointer import get_checkpointer
from agents.triage import triage_node
from agents.forensics import forensics_node
from agents.neutralizer import neutralizer_node
from agents.responder import uicr_compress, generate_report
from execution.wrapper import execute_action

logger = logging.getLogger("soar.graph")


def hitl_gate_node(state: UICRState) -> UICRState:
    """
    The Human-in-the-Loop Interrupt Gate.

    interrupt() raises a special LangGraph control-flow signal that pauses
    the graph and persists the current state via the checkpointer. The
    caller (FastAPI/Streamlit) is responsible for:
      1. Detecting the paused state (graph.get_state() shows next=("hitl_gate_node",)
         or similar, depending on LangGraph version).
      2. Starting a 300-second countdown (config.hitl.timeout_seconds) on
         their own side — LangGraph does not run a background timer for you.
      3. Either resuming with Command(resume={"decision": "APPROVED"|"REJECTED"})
         when the operator acts, OR resuming with
         Command(resume={"decision": "TIMEOUT"}) if 300s elapse with no input.

    The payload returned by interrupt() (the dict passed as its argument) is
    what the dashboard reads to render the Operator Action panel — the
    structural payload JSON and the decision buttons.
    """
    state["current_phase"] = PipelinePhase.AWAITING_HITL.value

    operator_input = interrupt(
        {
            "incident_id": state["incident_id"],
            "action_plan": state["action_plan"],
            "forensics_summary": (state.get("forensics") or {}).get("rag_timeline_notes"),
            "timeout_seconds": 300,
        }
    )

    # operator_input is whatever dict was passed into Command(resume=...).
    decision = operator_input.get("decision", HitlDecision.TIMEOUT.value)
    state["hitl_decision"] = decision
    return state


def route_after_forensics(state: UICRState) -> str:
    """The ONLY place the hard 0.70 threshold decision is acted on."""
    forensics = state.get("forensics") or {}
    if forensics.get("cleared_threshold") is True:
        return "neutralizer"
    return "uicr_compress"  # bypass neutralizer entirely -> escalation report


def route_after_hitl(state: UICRState) -> str:
    """The ONLY place hitl_decision branches the graph."""
    decision = state.get("hitl_decision")
    if decision == HitlDecision.APPROVED.value:
        return "execute_action"
    # REJECTED and TIMEOUT both skip the execution wrapper entirely.
    return "uicr_compress"


def build_graph():
    graph = StateGraph(UICRState)

    graph.add_node("triage", triage_node)
    graph.add_node("forensics", forensics_node)
    graph.add_node("neutralizer", neutralizer_node)
    graph.add_node("hitl_gate_node", hitl_gate_node)
    graph.add_node("execute_action", execute_action)
    graph.add_node("uicr_compress", uicr_compress)
    graph.add_node("generate_report", generate_report)

    graph.set_entry_point("triage")
    graph.add_edge("triage", "forensics")

    graph.add_conditional_edges(
        "forensics",
        route_after_forensics,
        {"neutralizer": "neutralizer", "uicr_compress": "uicr_compress"},
    )

    graph.add_edge("neutralizer", "hitl_gate_node")

    graph.add_conditional_edges(
        "hitl_gate_node",
        route_after_hitl,
        {"execute_action": "execute_action", "uicr_compress": "uicr_compress"},
    )

    graph.add_edge("execute_action", "uicr_compress")
    graph.add_edge("uicr_compress", "generate_report")
    graph.add_edge("generate_report", END)

    checkpointer = get_checkpointer()
    return graph.compile(checkpointer=checkpointer)


# Module-level compiled graph, built once per process.
compiled_graph = None


def get_compiled_graph():
    global compiled_graph
    if compiled_graph is None:
        compiled_graph = build_graph()
    return compiled_graph
