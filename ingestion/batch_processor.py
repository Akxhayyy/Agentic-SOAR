"""
ingestion/batch_processor.py

Stage 3: orchestrates the full hybrid pre-screening flow over an uploaded
log file, then hands each resulting IncidentGroup to the EXISTING,
unmodified graph pipeline (core/graph.py) — one incident per group.

Nothing about agents/triage.py, agents/forensics.py, agents/neutralizer.py,
the HITL gate, or execution/wrapper.py changes. This module only decides
WHAT becomes an incident; everything downstream of that decision is the
same code already verified to work.

Flow:
  1. parse_log_file()        -> every line, suspicious or not (for audit/visibility)
  2. filter_suspicious()      -> cheap, zero-LLM-cost gate
  3. group_suspicious_entries() -> cluster related suspicious lines
  4. for each group: build a RawLogEntry-compatible payload, create a new
     UICR via new_incident_state(), and invoke the SAME compiled graph
     used by the single-log /ingest path.

Returns a summary so the caller (FastAPI endpoint) can report back how
many lines were scanned, how many were flagged, and what incident_ids
were created — useful both for the dashboard and for your own sanity
when testing against a big file.
"""

from __future__ import annotations

import logging

from core.uicr_schema import RawLogEntry, new_incident_state
from core.checkpointer import thread_config_for_incident
from core.graph import get_compiled_graph
from ingestion.cheap_filter import parse_log_file, filter_suspicious
from ingestion.grouping import group_suspicious_entries, IncidentGroup

logger = logging.getLogger("soar.batch_processor")


def process_log_file(
    file_text: str, 
    default_log_type: str = "GENERIC", 
    delimiter: str | None = None
) -> dict:
    """
    Main entry point. Returns a summary dict:
        {
            "total_lines": int,
            "suspicious_lines": int,
            "incident_groups_created": int,
            "incidents": [{"incident_id": ..., "group_key": ..., "line_count": ...}, ...],
            "skipped_benign_count": int,
        }

    Each incident in the returned list is fully run through the graph
    SYNCHRONOUSLY before this function returns — for a large file with many
    suspicious groups, this can take a while, since every group triggers at
    least one Qwen call (Triage), and possibly several more (Forensics
    re-rank, Neutralizer, Responder). Callers running this from an async
    context (see main.py's /ingest_file endpoint) should run it via
    asyncio.to_thread, same pattern as the existing single-log /ingest path.
    """
    all_lines = parse_log_file(file_text, default_log_type=default_log_type, delimiter=delimiter)
    suspicious = filter_suspicious(all_lines)
    groups = group_suspicious_entries(suspicious, all_lines=all_lines)

    logger.info(
        "Batch ingest: %d total lines, %d flagged suspicious, %d incident groups formed",
        len(all_lines), len(suspicious), len(groups),
    )

    graph = get_compiled_graph()
    created_incidents = []

    for group in groups:
        incident_summary = _run_group_as_incident(group, graph)
        created_incidents.append(incident_summary)

    return {
        "total_lines": len(all_lines),
        "suspicious_lines": len(suspicious),
        "incident_groups_created": len(groups),
        "incidents": created_incidents,
        "skipped_benign_count": len(all_lines) - len(suspicious),
    }


def _run_group_as_incident(group: IncidentGroup, graph) -> dict:
    """
    Builds a UICR for one IncidentGroup and runs it through the existing
    compiled graph, exactly as the single-log /ingest endpoint does.

    IMPORTANT: each line in the group is validated as its OWN RawLogEntry
    (not concatenated into one string) so a multi-line burst never gets
    silently truncated by RawLogEntry's 1024-char hostile-boundary cap.
    agents/triage.py already joins all of state["raw_logs"] into one blob
    for the LLM prompt — that join happens AFTER each entry was validated
    individually, so the per-entry security cap stays intact while Qwen
    still sees the full multi-line pattern.
    """
    validated_entries = [
        RawLogEntry(
            source="batch_upload",
            log_type=line.log_type,
            raw_text=line.raw_text,  # already capped to 1024 in cheap_filter.py
        ).model_dump(mode="json")
        for line in group.lines
    ]

    state = new_incident_state()
    state["raw_logs"] = validated_entries

    config = thread_config_for_incident(state["incident_id"])

    try:
        result = graph.invoke(state, config)
        phase_reached = result.get("current_phase")
        threat_status = result.get("threat_status")
    except Exception as e:  # noqa: BLE001 — one bad group must not kill the whole batch
        logger.exception("Incident graph invocation failed for group %s", group.group_key)
        phase_reached = "ERROR"
        threat_status = "ERROR"

    return {
        "incident_id": state["incident_id"],
        "group_key": group.group_key,
        "line_count": len(group.lines),
        "phase_reached": phase_reached,
        "threat_status": threat_status,
    }
