"""
ingestion/batch_processor.py

Stage 3: orchestrates the hybrid pre-screening flow over an uploaded log
file, then hands each resulting IncidentGroup to the SAME compiled graph
used by single-log ingestion — one incident per group.

Flow:
  1. parse_log_file()            -> every line, suspicious or not
  2. filter_suspicious()         -> cheap, zero-LLM-cost gate
  3. group_suspicious_entries()  -> cluster related suspicious lines
  4. for each group: validate each line as its own RawLogEntry, create a
     UICR, and invoke the graph.

preview_log_file() runs steps 1-3 only (no LLM cost) so the UI can show
which lines were flagged and which incidents WOULD be created before the
operator commits GPU time.
"""

from __future__ import annotations

import logging
import uuid
from typing import Callable

from core.uicr_schema import RawLogEntry, new_incident_state
from core.checkpointer import thread_config_for_incident
from core.graph import get_compiled_graph
from ingestion.cheap_filter import ParsedLogLine, filter_suspicious, parse_log_file
from ingestion import log_store
from ingestion.grouping import IncidentGroup, group_suspicious_entries

logger = logging.getLogger("soar.batch_processor")

PREVIEW_LINE_LIMIT = 500


def _screen(file_text: str, default_log_type: str, delimiter: str | None):
    all_lines = parse_log_file(file_text, default_log_type=default_log_type, delimiter=delimiter)
    suspicious = filter_suspicious(all_lines)
    groups = group_suspicious_entries(suspicious, all_lines=all_lines)
    return all_lines, suspicious, groups


def _line_view(line: ParsedLogLine) -> dict:
    return {
        "raw_text": line.raw_text,
        "log_type": line.log_type,
        "timestamp": line.timestamp.isoformat() if line.timestamp else None,
        "ip": line.extracted_ip,
        "user": line.extracted_user,
        "suspicious": line.is_suspicious,
        "reason": line.match_reason,
        "success_login": line.is_success_login,
    }


def preview_log_file(file_text: str, default_log_type: str = "GENERIC", delimiter: str | None = None) -> dict:
    """Parse + filter + group with ZERO LLM calls. Safe to call on every keystroke."""
    all_lines, suspicious, groups = _screen(file_text, default_log_type, delimiter)
    return {
        "total_lines": len(all_lines),
        "suspicious_lines": len(suspicious),
        "filtered_out_pct": round(100 * (1 - len(suspicious) / len(all_lines)), 1) if all_lines else 0.0,
        "lines": [_line_view(l) for l in all_lines[:PREVIEW_LINE_LIMIT]],
        "truncated": len(all_lines) > PREVIEW_LINE_LIMIT,
        "groups": [
            {"group_key": g.group_key, "line_count": len(g.lines), "log_type": g.primary_log_type}
            for g in groups
        ],
    }


def process_log_file(
    file_text: str,
    default_log_type: str = "GENERIC",
    delimiter: str | None = None,
    on_incident: Callable[[dict], None] | None = None,
    on_groups: Callable[[list[IncidentGroup]], None] | None = None,
) -> dict:
    """
    Runs every suspicious group through the graph, synchronously. Callers in
    an async context must use asyncio.to_thread (see main.py jobs).

    on_groups(groups) fires once after screening; on_incident(summary) fires
    after each group finishes (or pauses at HITL) — used for job progress.
    """
    all_lines, suspicious, groups = _screen(file_text, default_log_type, delimiter)
    logger.info(
        "Batch ingest: %d total lines, %d flagged suspicious, %d incident groups formed",
        len(all_lines), len(suspicious), len(groups),
    )
    try:
        log_store.add_lines(str(uuid.uuid4()), all_lines)  # context for the forensics agent
    except Exception:  # noqa: BLE001 — enrichment only; never block ingestion
        logger.exception("Failed to persist lines to the log store")
    if on_groups:
        on_groups(groups)

    graph = get_compiled_graph()
    created = []
    for group in groups:
        summary = _run_group_as_incident(group, graph)
        created.append(summary)
        if on_incident:
            on_incident(summary)

    return {
        "total_lines": len(all_lines),
        "suspicious_lines": len(suspicious),
        "incident_groups_created": len(groups),
        "incidents": created,
        "skipped_benign_count": len(all_lines) - len(suspicious),
    }


def _run_group_as_incident(group: IncidentGroup, graph) -> dict:
    """
    Each line is validated as its OWN RawLogEntry (not concatenated) so a
    multi-line burst never gets truncated by the 1024-char hostile-boundary
    cap; triage joins them after per-entry validation.
    """
    validated_entries = [
        RawLogEntry(source="batch_upload", log_type=line.log_type, raw_text=line.raw_text).model_dump(mode="json")
        for line in group.lines
    ]

    state = new_incident_state(group_key=group.group_key)
    state["raw_logs"] = validated_entries
    stamps = sorted(l.timestamp for l in group.lines if l.timestamp)
    if stamps:
        state["time_window"] = {"first_seen": stamps[0].isoformat(), "last_seen": stamps[-1].isoformat()}
    config = thread_config_for_incident(state["incident_id"])

    try:
        result = graph.invoke(state, config)
        phase_reached = result.get("current_phase")
        threat_status = result.get("threat_status")
    except Exception:  # noqa: BLE001 — one bad group must not kill the whole batch
        logger.exception("Incident graph invocation failed for group %s", group.group_key)
        phase_reached = "FAILED"
        threat_status = "ESCALATED"

    return {
        "incident_id": state["incident_id"],
        "group_key": group.group_key,
        "line_count": len(group.lines),
        "phase_reached": phase_reached,
        "threat_status": threat_status,
    }
