"""
agents/responder.py

The Optimization & Responder Node — two responsibilities, run in sequence:

1. uicr_compress(state): a deterministic (no LLM call) pruning pass that
   truncates heavy fields (raw log text, playbook chunk text) before the
   final report-writing LLM call, and logs the measured byte reduction.

2. generate_report(state):
   - resolves the FINAL threat status (resolve_threat_status — the single
     place the lifecycle is decided: CONTAINED / CLOSED / ESCALATED / OPEN),
   - writes a Markdown report whose facts section is rendered
     DETERMINISTICALLY from the UICR (the LLM can't misstate an IOC, hash
     or decision), plus an LLM-written analyst narrative.
   If the LLM is unavailable the report is still written, without the
   narrative — an incident must never end without an audit record.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from core.uicr_schema import ActionType, HitlDecision, PipelinePhase, ThreatStatus, UICRState
from core.graph_config import load_config, reasoning_model_for
from agents.llm_client import call_reasoning_model, strip_fences

logger = logging.getLogger("soar.responder")

RAW_LOG_TRUNCATE_CHARS = 200
CHUNK_TEXT_TRUNCATE_CHARS = 200
NARRATIVE_CONTEXT_CHAR_BUDGET = 6000  # ~1.5k tokens, well inside num_ctx with the system prompt


def uicr_compress(state: UICRState) -> UICRState:
    """Deterministic pruning pass. No LLM call. Mutates and returns state."""
    before_size = len(json.dumps(state, default=str))

    for entry in state.get("raw_logs") or []:
        if len(entry.get("raw_text", "")) > RAW_LOG_TRUNCATE_CHARS:
            entry["raw_text"] = entry["raw_text"][:RAW_LOG_TRUNCATE_CHARS] + "...[truncated by uicr_compress]"

    for match in (state.get("forensics") or {}).get("matches") or []:
        if len(match.get("chunk_text", "")) > CHUNK_TEXT_TRUNCATE_CHARS:
            match["chunk_text"] = match["chunk_text"][:CHUNK_TEXT_TRUNCATE_CHARS] + "...[truncated by uicr_compress]"

    after_size = len(json.dumps(state, default=str))
    reduction_pct = 0.0 if before_size == 0 else round((1 - after_size / before_size) * 100, 1)
    logger.info(
        "uicr_compress: %d bytes -> %d bytes (%.1f%% reduction) for incident %s",
        before_size, after_size, reduction_pct, state.get("incident_id"),
    )

    state["compressed"] = True
    if state.get("current_phase") != PipelinePhase.FAILED.value:
        state["current_phase"] = PipelinePhase.COMPRESSING.value
    return state


def resolve_threat_status(state: UICRState) -> str:
    """The ONLY place the final threat status is decided."""
    if state.get("error"):
        return ThreatStatus.ESCALATED.value
    forensics = state.get("forensics") or {}
    if forensics.get("cleared_threshold") is not True:
        return ThreatStatus.ESCALATED.value
    if (state.get("action_plan") or {}).get("grounded") is False:
        return ThreatStatus.ESCALATED.value
    decision = state.get("hitl_decision")
    if decision == HitlDecision.TIMEOUT.value:
        return ThreatStatus.ESCALATED.value
    if decision == HitlDecision.REJECTED.value:
        return ThreatStatus.OPEN.value
    if decision == HitlDecision.APPROVED.value:
        result = state.get("execution_result") or {}
        if not result.get("success"):
            return ThreatStatus.ESCALATED.value
        if result.get("action_type") == ActionType.NO_ACTION.value:
            return ThreatStatus.CLOSED.value
        return ThreatStatus.CONTAINED.value
    return ThreatStatus.OPEN.value


def escalation_reason(state: UICRState) -> str | None:
    if state.get("error"):
        return f"Pipeline failure: {state['error']}"
    forensics = state.get("forensics") or {}
    if forensics.get("cleared_threshold") is not True:
        return "Forensics confidence below the hard threshold — no playbook clearly applies."
    plan = state.get("action_plan") or {}
    if plan.get("grounded") is False:
        return f"Proposed containment was blocked by the evidence-grounding check: {plan.get('grounding_note')}"
    decision = state.get("hitl_decision")
    if decision == HitlDecision.TIMEOUT.value:
        return "No operator decision before the HITL timeout."
    if decision == HitlDecision.REJECTED.value:
        return "Operator rejected the proposed containment; threat remains open."
    result = state.get("execution_result") or {}
    if decision == HitlDecision.APPROVED.value and not result.get("success"):
        return f"Approved action failed to execute: {result.get('error_message')}"
    return None


REPORT_SYSTEM_PROMPT = """You are a SOC analyst writing the narrative section of an incident report.
Using ONLY the incident record provided, write Markdown with exactly these sections:
### Executive Summary
(2-4 sentences: what happened, how it was handled, current status)
### Analyst Assessment
(short bullet list: key evidence and confidence)
### Recommended Next Steps
(3-5 bullets)
Do not repeat raw IDs or hashes. Do not invent facts. No preamble, no code fences."""


def _narrative_context(state: UICRState) -> str:
    triage = state.get("triage") or {}
    forensics = state.get("forensics") or {}
    plan = state.get("action_plan") or {}
    result = state.get("execution_result") or {}
    ctx = {
        "attack_vector": triage.get("attack_vector"),
        "triage_summary": triage.get("triage_summary"),
        "triage_confidence": triage.get("triage_confidence"),
        "iocs": triage.get("iocs"),
        "forensics": {
            "score": forensics.get("final_similarity_score"),
            "cleared": forensics.get("cleared_threshold"),
            "playbook": forensics.get("best_playbook"),
            "notes": forensics.get("rag_timeline_notes"),
        },
        "action_plan": {k: plan.get(k) for k in ("action_type", "target", "justification", "grounded", "grounding_note")},
        "hitl_decision": state.get("hitl_decision"),
        "operator_note": state.get("hitl_operator_note"),
        "execution": {k: result.get(k) for k in ("success", "dry_run", "error_message")},
        "threat_status": state.get("threat_status"),
        "escalation_reason": escalation_reason(state),
        "log_sample": [e.get("raw_text") for e in (state.get("raw_logs") or [])[:8]],
    }
    return json.dumps(ctx, default=str, indent=1)[:NARRATIVE_CONTEXT_CHAR_BUDGET]


def _facts_markdown(state: UICRState, escalation: str | None) -> str:
    triage = state.get("triage") or {}
    forensics = state.get("forensics") or {}
    plan = state.get("action_plan") or {}
    result = state.get("execution_result") or {}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    lines = ["# Escalation Required", "", f"> **{escalation}**", ""] if escalation else ["# Incident Report", ""]
    lines += [
        "| Field | Value |",
        "|---|---|",
        f"| Incident ID | `{state.get('incident_id')}` |",
        f"| Created | {state.get('created_at')} |",
        f"| Report generated | {now} |",
        f"| Source group | {state.get('group_key') or 'single ingest'} |",
        f"| Attack vector | {triage.get('attack_vector', 'n/a')} |",
        f"| Threat status | **{state.get('threat_status')}** |",
        f"| HITL decision | {state.get('hitl_decision')} |",
        "",
        "## Indicators of Compromise",
    ]
    iocs = triage.get("iocs") or []
    if iocs:
        lines += ["| Type | Value | Confidence |", "|---|---|---|"]
        lines += [f"| {i['ioc_type']} | `{i['value']}` | {i['confidence']:.2f} |" for i in iocs]
    else:
        lines.append("_None extracted._")
    lines += [
        "",
        "## Forensics",
        f"- Best playbook: {forensics.get('best_playbook') or 'none'}",
        f"- Final score: {forensics.get('final_similarity_score', 0.0):.3f} "
        f"({'cleared' if forensics.get('cleared_threshold') else 'did not clear'} threshold, "
        f"{forensics.get('pass_count', '-')} pass(es))",
        f"- Notes: {forensics.get('rag_timeline_notes') or '-'}",
    ]
    if plan:
        lines += [
            "",
            "## Containment Plan",
            f"- Action: **{plan.get('action_type')}** on `{plan.get('target')}`",
            f"- Justification: {plan.get('justification')}",
            f"- Evidence grounding: {'passed' if plan.get('grounded') else 'FAILED'} — {plan.get('grounding_note') or '-'}",
            f"- Payload SHA-256: `{plan.get('payload_hash')}`",
        ]
    if state.get("hitl_operator_note"):
        lines += ["", f"**Operator note:** {state['hitl_operator_note']}"]
    if result:
        lines += [
            "",
            "## Execution",
            f"- Success: {result.get('success')} · Dry run: {result.get('dry_run')} · "
            f"Hash verified: {result.get('hash_verified')}",
        ]
        if result.get("error_message"):
            lines.append(f"- Error: {result['error_message']}")
    return "\n".join(lines)


def generate_report(state: UICRState) -> UICRState:
    if not state.get("compressed"):
        logger.warning("generate_report called before uicr_compress for %s — compressing now.",
                       state.get("incident_id"))
        state = uicr_compress(state)

    # Status FIRST, so the report (and its banner) reflect the final value.
    state["threat_status"] = resolve_threat_status(state)
    escalation = escalation_reason(state)

    try:
        narrative = strip_fences(call_reasoning_model(
            system_prompt=REPORT_SYSTEM_PROMPT,
            user_prompt=f"Incident record:\n{_narrative_context(state)}",
            max_tokens=600,
            **reasoning_model_for("report"),
        ))
    except Exception as e:  # noqa: BLE001 — the report must be written regardless
        logger.warning("Report narrative unavailable for %s: %s", state.get("incident_id"), e)
        narrative = "_Analyst narrative unavailable (reasoning model offline)._"

    report_md = _facts_markdown(state, escalation) + "\n\n## Analyst Narrative\n\n" + narrative + "\n"

    report_dir = Path(load_config()["execution"]["report_dir"])
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"incident_{state.get('incident_id')}.md"
    report_path.write_text(report_md, encoding="utf-8")

    state["report_path"] = str(report_path)
    if state.get("current_phase") != PipelinePhase.FAILED.value:
        state["current_phase"] = PipelinePhase.REPORTED.value
    logger.info("Report written to %s (status=%s)", report_path, state["threat_status"])
    return state
