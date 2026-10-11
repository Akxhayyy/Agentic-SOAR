"""
agents/neutralizer.py

Neutralizer Agent Node — formulates the structured ActionPlan and computes
the SHA-256 payload_hash that the execution wrapper will independently
recompute and verify before acting.

IMPORTANT: this node has ZERO ability to execute anything. It only ever
writes a plan into state["action_plan"]. There is no shell access, no
subprocess import, no eval, nothing here that could act on the host even if
the LLM output were maximally adversarial.

Evidence grounding (the main defence against prompt injection via logs):
the raw logs are attacker-controlled and reach the LLM prompt, so the
model's proposed `target` is NEVER trusted on its own. After parsing, the
target must
  1. exactly match an IOC value the Triage agent extracted (and Triage only
     keeps IOCs that literally appear in the logs),
  2. be an IOC type that makes sense for the action (you lock a USERNAME,
     you block an IP_ADDRESS, ...), and
  3. not be on the configured protected-asset deny-list
     (execution.protected_targets + this machine's hostname).
Any failure downgrades the plan to NO_ACTION with the reason recorded, so
the operator sees exactly why. Previously a plan could target a value that
appeared nowhere in the evidence (e.g. `user@example.com`).

Hash contract: payload_hash = SHA256(canonical_json({action_type, target,
params})). Both this node and execution/wrapper.py MUST use the exact same
serialization, or every legitimate plan would fail verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import socket

from pydantic import BaseModel, Field, ValidationError

from core.uicr_schema import ActionPlan, ActionType, IOCType, PipelinePhase, UICRState
from core.graph_config import load_config, reasoning_model_for
from agents.llm_client import call_reasoning_model, parse_json_response, strict_schema

logger = logging.getLogger("soar.neutralizer")

# Which IOC types each action may legitimately target.
ACTION_TARGET_TYPES: dict[ActionType, set[IOCType]] = {
    ActionType.ISOLATE_HOST: {IOCType.HOSTNAME, IOCType.IP_ADDRESS},
    ActionType.LOCK_ACCOUNT: {IOCType.USERNAME},
    ActionType.QUARANTINE_PROCESS: {IOCType.PROCESS_NAME, IOCType.FILE_HASH},
    ActionType.TERMINATE_PROCESS: {IOCType.PROCESS_NAME},
    ActionType.BLOCK_PROXY_IP: {IOCType.IP_ADDRESS},
}

NEUTRALIZER_SYSTEM_PROMPT = """You are a SOC containment planner. Choose ONE containment action
for the incident, using the playbook guidance provided. Respond with JSON only.

Fields:
- action_type: one of ISOLATE_HOST, LOCK_ACCOUNT, QUARANTINE_PROCESS, TERMINATE_PROCESS,
  BLOCK_PROXY_IP, NO_ACTION.
- target: copy EXACTLY one value from the "Available targets" list. Never invent a target.
- params: object of extra string parameters (may be empty).
- justification: 1-3 sentences (max 500 chars) citing the evidence and playbook step.

Action/target compatibility:
- LOCK_ACCOUNT -> a USERNAME target
- ISOLATE_HOST -> a HOSTNAME or IP_ADDRESS target
- BLOCK_PROXY_IP -> an IP_ADDRESS target
- TERMINATE_PROCESS -> a PROCESS_NAME target (malware, reverse shells). Prefer the numeric
  PID when one is available: terminating by image name kills EVERY process with that name.
- QUARANTINE_PROCESS -> a PROCESS_NAME or FILE_HASH target
If no available target fits, or the evidence does not clearly support containment,
use NO_ACTION with target "none".
"""


class _PlanOutput(BaseModel):
    action_type: ActionType
    target: str = Field(..., max_length=256)
    params: dict[str, str] = Field(default_factory=dict)
    justification: str = Field(..., max_length=2000)


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


def protected_targets() -> set[str]:
    cfg = load_config()["execution"]
    names = {str(t).lower() for t in cfg.get("protected_targets", [])}
    try:
        names.add(socket.gethostname().lower())
    except OSError:
        pass
    return names


def check_grounding(action_type: ActionType, target: str, iocs: list[dict]) -> tuple[bool, str]:
    """Returns (ok, note). Pure function so it can be unit-tested directly."""
    if action_type == ActionType.NO_ACTION:
        return True, "No action proposed."
    security = load_config()["security"]
    if security["deny_list"] and target.lower() in protected_targets():
        return False, f"Target '{target}' is a protected asset."
    if not security["grounding"]:
        return True, "Grounding check disabled (red-team mode)."
    allowed = ACTION_TARGET_TYPES.get(action_type, set())
    matches = [i for i in iocs if i.get("value", "").lower() == target.lower()]
    if not matches:
        return False, f"Target '{target}' does not appear in the extracted IOCs."
    if not any(IOCType(i["ioc_type"]) in allowed for i in matches):
        types = ", ".join(sorted({i["ioc_type"] for i in matches}))
        return False, f"{action_type.value} cannot target a {types} IOC."
    return True, f"Target matches extracted {matches[0]['ioc_type']} IOC."


def _playbook_guidance(forensics: dict) -> str:
    """Containment text from the best-matching playbook (the RAG payoff)."""
    matches = forensics.get("matches") or []
    best = forensics.get("best_playbook")
    same_book = [m for m in matches if m.get("playbook_id") == best] or matches
    containment = [m for m in same_book if "containment" in m.get("chunk_text", "").lower()]
    chosen = (containment or same_book)[:2]
    return "\n---\n".join(m["chunk_text"][:1200] for m in chosen) or "(no playbook text)"


def plan_schema(iocs: list[dict]) -> dict:
    """
    JSON schema for the LLM output. With grounding on, `target` is an enum of
    the extracted IOC values (+ "none"), so Ollama's grammar-constrained
    decoding can only emit an exact, evidence-backed value — the model can't
    invent a target or decorate one ("USERNAME: admin").
    """
    schema = strict_schema(_PlanOutput)
    if not load_config()["security"]["grounding"]:
        return schema

    # One anyOf branch per action that has at least one type-compatible IOC,
    # each pinning action_type (const) and target (enum of compatible values).
    # Invalid pairs like TERMINATE_PROCESS on a USERNAME become ungeneratable.
    props = schema["properties"]
    branches = []
    for action, allowed in ACTION_TARGET_TYPES.items():
        values = list(dict.fromkeys(i["value"] for i in iocs if IOCType(i["ioc_type"]) in allowed))
        if values:
            branches.append(_branch(props, action.value, values))
    branches.append(_branch(props, ActionType.NO_ACTION.value, ["none"]))
    return {
        "type": "object",
        "anyOf": branches,
        "required": ["action_type", "target", "params", "justification"],
    }


def _branch(props: dict, action: str, targets: list[str]) -> dict:
    return {
        "type": "object",
        "properties": {
            "action_type": {"type": "string", "const": action},
            "target": {"type": "string", "enum": targets},
            "params": props["params"],
            "justification": props["justification"],
        },
        "required": ["action_type", "target", "params", "justification"],
    }


def _no_action(reason: str) -> ActionPlan:
    return ActionPlan(
        action_type=ActionType.NO_ACTION,
        target="none",
        params={},
        justification=reason[:512],
        payload_hash=_compute_payload_hash(ActionType.NO_ACTION.value, "none", {}),
        grounded=True,
        grounding_note="",
    )


def neutralizer_node(state: UICRState) -> UICRState:
    forensics = state.get("forensics") or {}
    triage = state.get("triage") or {}
    iocs = triage.get("iocs", [])

    intel = forensics.get("intel_hits") or []
    intel_block = "\n".join(
        f"- {h.get('ioc')}: {h.get('severity', '').upper()} {h.get('description', '')}" for h in intel[:5]
    ) or "- no threat-intel matches"
    targets_block ="\n".join(f"- {i['value']}  (type {i['ioc_type']})" for i in iocs) or "- (none)"
    evidence_block = (
        f"Attack vector: {triage.get('attack_vector', 'UNKNOWN')}\n"
        f"Triage summary: {triage.get('triage_summary', '')}\n"
        f"Forensics confidence: {forensics.get('final_similarity_score', 0.0):.3f} "
        f"(matched playbook: {forensics.get('best_playbook') or 'n/a'})\n\n"
        f"Forensics investigation: {forensics.get('agent_rationale') or forensics.get('rag_timeline_notes', '')}\n"
        f"Related log lines around the incident: {forensics.get('related_log_count', 0)}\n"
        f"Threat intel:\n{intel_block}\n\n"
        f"Available targets:\n{targets_block}\n\n"
        f"Playbook guidance:\n{_playbook_guidance(forensics)}"
    )

    raw_response = call_reasoning_model(
        system_prompt=NEUTRALIZER_SYSTEM_PROMPT,
        user_prompt=evidence_block,
        schema=plan_schema(iocs),
        max_tokens=400,
        **reasoning_model_for("neutralizer"),
    )

    try:
        payload = parse_json_response(raw_response)
        # Models sometimes emit numbers/bools as param values; coerce to str
        # rather than discarding an otherwise valid plan.
        if isinstance(payload.get("params"), dict):
            payload["params"] = {str(k): str(v) for k, v in payload["params"].items()}
        out = _PlanOutput(**payload)
        target = out.target.strip()

        if target.lower() == "none" and out.action_type != ActionType.NO_ACTION:
            out = _PlanOutput(
                action_type=ActionType.NO_ACTION, target="none", params={},
                justification=f"Model proposed {out.action_type.value} but no extracted IOC is a valid "
                              f"target for it. {out.justification}"[:2000],
            )
        ok, note = check_grounding(out.action_type, target, iocs)
        if not ok:
            logger.warning("Neutralizer plan rejected by grounding check: %s", note)
            plan = _no_action(
                f"Proposed {out.action_type.value} on '{target[:64]}' was blocked: {note} "
                "Manual review required."
            )
            plan.grounded = False
            plan.grounding_note = note[:256]
        elif out.action_type == ActionType.NO_ACTION:
            plan = _no_action(out.justification)
        else:
            plan = ActionPlan(
                action_type=out.action_type,
                target=target,
                params=out.params,
                justification=out.justification[:512],
                payload_hash=_compute_payload_hash(out.action_type.value, target, out.params),
                grounded=True,
                grounding_note=note[:256],
            )
    except (json.JSONDecodeError, ValidationError, ValueError, TypeError) as e:
        logger.error("Neutralizer plan failed validation, defaulting to NO_ACTION: %s", e)
        plan = _no_action(
            f"Automated plan generation failed validation ({type(e).__name__}); "
            "defaulting to no action pending manual review."
        )

    state["action_plan"] = plan.model_dump(mode="json")
    state["current_phase"] = PipelinePhase.NEUTRALIZER_PLANNED.value
    return state
