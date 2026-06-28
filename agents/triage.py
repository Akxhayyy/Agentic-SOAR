"""
agents/triage.py

Triage Agent Node — first stop after raw, untrusted logs enter the UICR.

Two-stage defense at this boundary:
  1. RawLogEntry (Pydantic) already capped/validated the incoming text
     before it ever reached UICRState.raw_logs (done at the FastAPI
     ingestion layer — see main.py).
  2. Here, we constrain the LLM's OUTPUT, not its input. The model never
     free-types an attack_vector string; it must select from the
     AttackVector enum, and every IOC it extracts is re-validated against
     IOCType + the SAFE_TOKEN_PATTERN charset allow-list before it's
     allowed into TriageResult. If the LLM hallucinates a value with bad
     characters, Pydantic raises and this node retries once with a
     stricter "extract nothing you cannot fit the schema" instruction,
     then falls back to UNKNOWN/empty IOCs rather than ever relaxing the
     schema to accommodate bad output.
"""

from __future__ import annotations

import json
import logging

from pydantic import ValidationError

from core.uicr_schema import (
    AttackVector,
    IOC,
    IOCType,
    PipelinePhase,
    TriageResult,
    UICRState,
)
from core.graph_config import load_config
from agents.llm_client import call_reasoning_model

logger = logging.getLogger("soar.triage")

TRIAGE_SYSTEM_PROMPT = """You are a security log triage parser. You output ONLY
valid JSON matching this exact schema, with no preamble or markdown fences:

{
  "attack_vector": one of ["NETWORK_INTRUSION","BRUTE_FORCE_AUTH","MALWARE_EXECUTION",
                            "DATA_EXFILTRATION","PRIVILEGE_ESCALATION","PROXY_ANOMALY","UNKNOWN"],
  "discovered_layout": string (max 256 chars, describing the discovered format of the input, e.g. "syslog", "CSV with header: ip,user,msg", "JSON line format", or "unstructured raw text"),
  "iocs": [{"ioc_type": one of ["IP_ADDRESS","HOSTNAME","USERNAME","PROCESS_NAME","FILE_HASH","PORT"],
            "value": string, "confidence": float 0-1}],
  "triage_summary": string (max 512 chars),
  "triage_confidence": float 0-1
}

Rules:
- If you cannot confidently classify the attack vector, use "UNKNOWN" — never invent a category.
- Only extract IOCs you can quote directly from the provided log text.
- IOC "value" must contain only word characters, dots, colons, hyphens, or @ — no quotes,
  no spaces, no shell metacharacters. If a candidate value contains anything else, omit it.
- Output strictly valid JSON. No commentary.
"""


def _attempt_parse(raw_json_text: str) -> TriageResult:
    payload = json.loads(raw_json_text)
    return TriageResult(**payload)


def triage_node(state: UICRState) -> UICRState:
    cfg = load_config()
    log_blob = "\n".join(entry["raw_text"] for entry in state["raw_logs"])

    # Token safety ceiling: Cap the combined log blob text to 8000 characters
    # (roughly 1600-2000 tokens) to ensure the 4096 context window limit is never exceeded.
    if len(log_blob) > 8000:
        log_blob = log_blob[:8000] + "...[truncated for token limit safety]"

    model_cfg = cfg["models"]["reasoning"]
    raw_response = call_reasoning_model(
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        user_prompt=f"Logs to triage:\n{log_blob}",
        model=model_cfg["model"],
        num_ctx=model_cfg["num_ctx"],
        temperature=model_cfg["temperature"],
    )

    try:
        result = _attempt_parse(raw_response)
    except (json.JSONDecodeError, ValidationError) as e:
        logger.warning("Triage parse failed on first attempt: %s", e)
        # Single retry with a stricter corrective instruction. No schema relaxation.
        corrective_prompt = (
            f"Your previous output failed schema validation: {e}\n"
            "Re-output STRICT valid JSON matching the schema exactly. "
            "If unsure, use attack_vector='UNKNOWN', discovered_layout='unknown format', and an empty iocs list."
        )
        raw_response_retry = call_reasoning_model(
            system_prompt=TRIAGE_SYSTEM_PROMPT,
            user_prompt=f"Logs to triage:\n{log_blob}\n\n{corrective_prompt}",
            model=model_cfg["model"],
            num_ctx=model_cfg["num_ctx"],
            temperature=model_cfg["temperature"],
        )
        try:
            result = _attempt_parse(raw_response_retry)
        except (json.JSONDecodeError, ValidationError) as e2:
            logger.error("Triage parse failed on retry, falling back to UNKNOWN: %s", e2)
            result = TriageResult(
                attack_vector=AttackVector.UNKNOWN,
                discovered_layout="unknown format (fallback)",
                iocs=[],
                triage_summary="Automated triage failed schema validation twice; "
                               "manual review required.",
                triage_confidence=0.0,
            )

    state["triage"] = result.model_dump(mode="json")
    state["current_phase"] = PipelinePhase.TRIAGED.value
    return state
