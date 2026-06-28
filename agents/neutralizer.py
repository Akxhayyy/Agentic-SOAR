"""
agents/neutralizer.py

Neutralizer Agent Node — formulates the structured ActionPlan and computes
the SHA-256 payload_hash that the execution wrapper will independently
recompute and verify before acting.

IMPORTANT: this node has ZERO ability to execute anything. It only ever
writes a plan into state["action_plan"]. There is no shell access, no
subprocess import, no eval, nothing here that could act on the host even if
the LLM output were maximally adversarial — the worst case is a plan with a
bad payload_hash, which the wrapper will reject on hash mismatch (see
execution/wrapper.py).

Hash contract: payload_hash = SHA256(canonical_json({action_type, target,
params})). "Canonical" means sorted keys, no extraneous whitespace — both
this node and the wrapper MUST use the exact same serialization, or every
legitimate plan would fail verification. _canonical_payload() is shared
logic; do not duplicate the json.dumps call elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import logging

from pydantic import ValidationError

from core.uicr_schema import ActionPlan, ActionType, PipelinePhase, UICRState
from core.graph_config import load_config
from agents.llm_client import call_reasoning_model

logger = logging.getLogger("soar.neutralizer")

NEUTRALIZER_SYSTEM_PROMPT = """You are a containment action planner. Output ONLY
valid JSON matching this schema, no preamble, no markdown fences:

{
  "action_type": one of ["ISOLATE_HOST","LOCK_ACCOUNT","QUARANTINE_PROCESS",
                          "TERMINATE_PROCESS","BLOCK_PROXY_IP","NO_ACTION"],
  "target": string (the host identifier, username, process name, or IP to act on),
  "params": {} (string-to-string map of any extra parameters, may be empty),
  "justification": string (max 512 chars, why this action given the forensics evidence)
}

Rules:
- "target" must contain only word characters, dots, colons, hyphens, or @ — no quotes,
  no spaces, no shell metacharacters.
- Use TERMINATE_PROCESS when malware execution or reverse shell processes must be killed.
- Use BLOCK_PROXY_IP when suspicious proxy traffic or C2 beaconing is detected through a proxy.
- If the forensics evidence does not clearly support any containment action, use
  action_type="NO_ACTION" and explain why in justification.
- Do NOT include payload_hash — that is computed separately after your output is parsed.
"""


def _canonical_payload(action_type: str, target: str, params: dict) -> str:
    """Shared canonical serialization — MUST match execution/wrapper.py exactly."""
    return json.dumps(
        {"action_type": action_type, "target": target, "params": params},
        sort_keys=True,
        separators=(",", ":"),
    )


def _compute_payload_hash(action_type: str, target: str, params: dict) -> str:
    canonical = _canonical_payload(action_type, target, params)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def neutralizer_node(state: UICRState) -> UICRState:
    cfg = load_config()
    forensics = state.get("forensics") or {}
    triage = state.get("triage") or {}

    evidence_block = (
        f"Triage summary: {triage.get('triage_summary', '')}\n"
        f"Attack vector: {triage.get('attack_vector', 'UNKNOWN')}\n"
        f"Forensics confidence: {forensics.get('final_similarity_score', 0.0)}\n"
        f"Matched playbook notes: {forensics.get('rag_timeline_notes', '')}"
    )

    model_cfg = cfg["models"]["reasoning"]
    raw_response = call_reasoning_model(
        system_prompt=NEUTRALIZER_SYSTEM_PROMPT,
        user_prompt=evidence_block,
        model=model_cfg["model"],
        num_ctx=model_cfg["num_ctx"],
        temperature=model_cfg["temperature"],
    )

    try:
        parsed = json.loads(raw_response)
        action_type = parsed["action_type"]
        target = parsed["target"]
        params = parsed.get("params", {})
        justification = parsed["justification"]

        payload_hash = _compute_payload_hash(action_type, target, params)

        plan = ActionPlan(
            action_type=ActionType(action_type),
            target=target,
            params=params,
            justification=justification,
            payload_hash=payload_hash,
        )
    except (json.JSONDecodeError, KeyError, ValueError, ValidationError) as e:
        logger.error("Neutralizer plan failed validation, defaulting to NO_ACTION: %s", e)
        payload_hash = _compute_payload_hash(ActionType.NO_ACTION.value, "none", {})
        plan = ActionPlan(
            action_type=ActionType.NO_ACTION,
            target="none",
            params={},
            justification=f"Automated plan generation failed validation ({e}); "
                          "defaulting to no action pending manual review.",
            payload_hash=payload_hash,
        )

    state["action_plan"] = plan.model_dump(mode="json")
    state["current_phase"] = PipelinePhase.NEUTRALIZER_PLANNED.value
    return state
