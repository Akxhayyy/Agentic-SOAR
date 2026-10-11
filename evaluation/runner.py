"""
evaluation/runner.py

Shared machinery for scripts/eval.py and scripts/redteam.py:

  isolated_runtime(run_dir, ...)  temporarily points every runtime path at
      run_dir (its own checkpoint DB, reports, exec results, log store,
      audit log), applies model / security / agent overrides, installs a
      fresh compiled graph, and restores everything on exit. It ALWAYS
      forces execution.dry_run = true: benchmark and red-team runs must
      never be able to touch the host, whatever the config file says.

  run_logs(graph, text, decision)  runs one log file through the real
      pipeline (cheap filter -> grouping -> graph), auto-resolves every
      HITL pause with `decision`, and returns the final incident states
      plus timing / token / filter statistics.
"""

from __future__ import annotations

import copy
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from langgraph.types import Command


@dataclass
class RunOutput:
    states: list[dict]
    total_lines: int
    flagged_lines: int
    elapsed_s: float
    usage: dict = field(default_factory=dict)


@contextmanager
def isolated_runtime(run_dir: Path, model: str | None = None, security: dict | None = None,
                     agent_enabled: bool | None = None):
    from langgraph.checkpoint.sqlite import SqliteSaver

    import core.graph as core_graph
    from core.graph_config import load_config

    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    cfg = load_config()
    saved = copy.deepcopy(cfg)
    saved_graph = core_graph.compiled_graph

    cfg["execution"].update(
        dry_run=True,  # non-negotiable for eval / red-team runs
        exec_result_dir=str(run_dir / "exec_results"),
        report_dir=str(run_dir / "reports"),
    )
    cfg["hitl"]["checkpointer_db_path"] = str(run_dir / "graph_state.db")
    cfg["logging"]["audit_log_path"] = str(run_dir / "audit.log")
    cfg["forensics"]["log_store_path"] = str(run_dir / "logstore.db")
    if model:
        cfg["models"]["reasoning"]["model"] = model
        cfg["models"]["reasoning"]["per_agent"] = {}
    if security:
        cfg["security"].update(security)
    if agent_enabled is not None:
        cfg["forensics"]["agent"]["enabled"] = agent_enabled

    conn = sqlite3.connect(cfg["hitl"]["checkpointer_db_path"], check_same_thread=False)
    graph = core_graph.build_graph(checkpointer=SqliteSaver(conn))
    core_graph.compiled_graph = graph
    try:
        yield graph
    finally:
        core_graph.compiled_graph = saved_graph
        conn.close()
        cfg.clear()
        cfg.update(saved)


def run_logs(graph, text: str, decision: str = "APPROVED") -> RunOutput:
    from agents.llm_client import reset_usage, usage_snapshot
    from core.checkpointer import thread_config_for_incident
    from ingestion.batch_processor import preview_log_file, process_log_file

    reset_usage()
    t0 = time.perf_counter()
    preview = preview_log_file(text)
    summary = process_log_file(text)
    states = []
    for inc in summary["incidents"]:
        cfg = thread_config_for_incident(inc["incident_id"])
        snap = graph.get_state(cfg)
        if snap.next:
            graph.invoke(Command(resume={"decision": decision, "note": "auto-decided by evaluation harness"}), cfg)
        states.append(graph.get_state(cfg).values)
    return RunOutput(
        states=states,
        total_lines=preview["total_lines"],
        flagged_lines=preview["suspicious_lines"],
        elapsed_s=round(time.perf_counter() - t0, 3),
        usage=usage_snapshot(),
    )


def primary_state(states: list[dict]) -> dict | None:
    """The incident with the most log lines represents the scenario."""
    if not states:
        return None
    return max(states, key=lambda s: len(s.get("raw_logs") or []))


def containment_executed(state: dict) -> bool:
    result = state.get("execution_result") or {}
    return bool(result.get("success")) and result.get("action_type") not in (None, "NO_ACTION")
