"""
agents/responder.py

The Optimization & Responder Node — two responsibilities, run in sequence:

1. uicr_compress(state): a deterministic (no LLM call) pruning pass that
   strips heavy fields from the UICR BEFORE the final report-writing LLM
   call. Specifically:
     - state["raw_logs"]: each entry's raw_text is truncated to 200 chars
       (kept for traceability, not full reproduction).
     - state["forensics"]["matches"]: each match's chunk_text is truncated
       to 200 chars (we keep playbook_id + score in full; the full chunk
       text was only ever needed during retrieval/reranking, not reporting).
   This is measured, not assumed — _compression_ratio() reports the actual
   byte reduction so you can verify the >30% target on real data rather
   than trusting a hardcoded comment.

2. generate_report(state): reads the COMPRESSED state and writes a Markdown
   audit summary to disk. Two templates: the normal incident report, and
   ESCALATION_REQUIRED_REPORT for the TIMEOUT/no-forensics-match paths,
   per your answer #3 (local-only visual alerting, no outbound calls).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from core.uicr_schema import HitlDecision, PipelinePhase, ThreatStatus, UICRState
from core.graph_config import load_config
from agents.llm_client import call_reasoning_model

logger = logging.getLogger("soar.responder")

RAW_LOG_TRUNCATE_CHARS = 200
CHUNK_TEXT_TRUNCATE_CHARS = 200


def uicr_compress(state: UICRState) -> UICRState:
    """Deterministic pruning pass. No LLM call. Mutates and returns state."""
    before_size = len(json.dumps(state, default=str))

    if state.get("raw_logs"):
        for entry in state["raw_logs"]:
            if "raw_text" in entry and len(entry["raw_text"]) > RAW_LOG_TRUNCATE_CHARS:
                entry["raw_text"] = (
                    entry["raw_text"][:RAW_LOG_TRUNCATE_CHARS] + "...[truncated by uicr_compress]"
                )

    forensics = state.get("forensics")
    if forensics and forensics.get("matches"):
        for match in forensics["matches"]:
            if "chunk_text" in match and len(match["chunk_text"]) > CHUNK_TEXT_TRUNCATE_CHARS:
                match["chunk_text"] = (
                    match["chunk_text"][:CHUNK_TEXT_TRUNCATE_CHARS]
                    + "...[truncated by uicr_compress]"
                )

    after_size = len(json.dumps(state, default=str))
    reduction_pct = 0.0 if before_size == 0 else round((1 - after_size / before_size) * 100, 1)
    logger.info(
        "uicr_compress: %d bytes -> %d bytes (%.1f%% reduction) for incident %s",
        before_size, after_size, reduction_pct, state.get("incident_id"),
    )

    state["compressed"] = True
    state["current_phase"] = PipelinePhase.COMPRESSING.value
    return state


REPORT_SYSTEM_PROMPT = """You write a professional security incident audit
summary in Markdown. Use the provided (already-compressed) incident record.
Be factual and concise — do not invent details not present in the record.
Output Markdown only, no preamble."""

ESCALATION_SYSTEM_PROMPT = """You write an URGENT escalation audit summary in
Markdown for a security incident that could NOT be automatically remediated
(forensics confidence below threshold, operator timeout, or operator
rejection). Lead with a clear escalation banner. Be factual and concise."""


def _build_report_context(state: UICRState) -> str:
    """Compressed-state context handed to the report-writing LLM call."""
    return json.dumps(
        {
            "incident_id": state.get("incident_id"),
            "created_at": state.get("created_at"),
            "triage": state.get("triage"),
            "forensics": state.get("forensics"),
            "action_plan": state.get("action_plan"),
            "execution_result": state.get("execution_result"),
            "hitl_decision": state.get("hitl_decision"),
            "threat_status": state.get("threat_status"),
        },
        default=str,
        indent=2,
    )


def _is_escalation_path(state: UICRState) -> bool:
    forensics = state.get("forensics") or {}
    hitl = state.get("hitl_decision")
    return (
        forensics.get("cleared_threshold") is False
        or hitl == HitlDecision.TIMEOUT.value
        or hitl == HitlDecision.REJECTED.value
    )


def generate_report(state: UICRState) -> UICRState:
    if not state.get("compressed"):
        logger.warning(
            "generate_report called before uicr_compress for incident %s — "
            "running compression now as a safety net.", state.get("incident_id"),
        )
        state = uicr_compress(state)

    cfg = load_config()
    model_cfg = cfg["models"]["reasoning"]
    context_block = _build_report_context(state)

    escalation = _is_escalation_path(state)
    system_prompt = ESCALATION_SYSTEM_PROMPT if escalation else REPORT_SYSTEM_PROMPT

    report_md = call_reasoning_model(
        system_prompt=system_prompt,
        user_prompt=f"Incident record:\n{context_block}",
        model=model_cfg["model"],
        num_ctx=model_cfg["num_ctx"],
        temperature=model_cfg["temperature"],
    )

    if escalation:
        banner = (
            "# 🔴 ESCALATION_REQUIRED_REPORT\n\n"
            f"**Incident ID:** `{state.get('incident_id')}`  \n"
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n"
            f"**HITL Decision:** {state.get('hitl_decision')}  \n"
            f"**Threat Status:** {state.get('threat_status')}  \n\n---\n\n"
        )
        report_md = banner + report_md
        if state.get("hitl_decision") == HitlDecision.TIMEOUT.value:
            state["threat_status"] = ThreatStatus.ESCALATED.value
        elif state.get("hitl_decision") == HitlDecision.REJECTED.value:
            state["threat_status"] = ThreatStatus.OPEN.value

    report_dir = Path("./data/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"incident_{state.get('incident_id')}.md"
    report_path.write_text(report_md, encoding="utf-8")

    state["report_path"] = str(report_path)
    state["current_phase"] = PipelinePhase.REPORTED.value
    logger.info("Report written to %s (escalation=%s)", report_path, escalation)
    return state
