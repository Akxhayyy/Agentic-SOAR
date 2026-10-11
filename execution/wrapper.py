"""
execution/wrapper.py

THE DETACHED EXECUTION WRAPPER NODE.

This module is intentionally the most boring, most defensively-written code
in the entire codebase. It is the ONLY code path with the authority to call
infrastructure APIs (real or stubbed). It must never import an LLM client,
never construct a shell command from a string, never call eval/exec, and
never trust any field on the incoming ActionPlan without re-validating it
independently of whatever validation already happened upstream.

Defense layers, in order, ALL of which must pass before any action fires:
  1. hash re-verification — recompute payload_hash from
     (action_type, target, params) using the exact same canonical
     serialization as neutralizer.py, and compare to the hash stored on
     the plan. Mismatch = the in-memory object was mutated after planning
     (e.g. by a bug, a race, or a worse actor) → ABORT, do not execute.
  2. regex charset re-check on `target` — SAFE_TOKEN_PATTERN, independently
     re-applied here even though Pydantic already enforced it on ActionPlan.
     This is deliberate duplication: it means a future code change that
     accidentally bypasses the Pydantic layer (e.g. constructing an
     ActionPlan via model_construct(), which skips validators) still can't
     reach the infra API with a dangerous target string.
  3. action_type allow-list dispatch — a plain if/elif over the ActionType
     enum, never a dynamic getattr(infra_api, action_type) call. Dynamic
     dispatch from untrusted strings is exactly the kind of "looks fine,
     is actually an injection vector" pattern this wrapper exists to avoid.
  4. DRY_RUN routing — config.execution.dry_run decides whether step 3
     calls execution.stub_infra_api or a real infra client. The two
     present IDENTICAL function signatures so swapping is a one-line
     change in production, not a rewrite.

Rollback contract: remove_host_isolation() and unlock_account() are exposed
here so an operator-facing control (dashboard button) can reverse a
containment action. They go through the exact same hash-free-but-charset-
checked dispatch pattern.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
from pathlib import Path

from core.uicr_schema import ActionPlan, ActionType, ExecutionResult, PipelinePhase, UICRState
from core.graph_config import load_config
from execution import stub_infra_api

logger = logging.getLogger("soar.execution_wrapper")

# Independently re-declared here rather than imported from core.uicr_schema —
# deliberate: this module must remain correct even if someone changes the
# schema module's import surface. Keep the literal pattern identical.
SAFE_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_.:\-@]+$")  # ASCII only: \w admits Unicode homoglyphs


def _canonical_payload(action_type: str, target: str, params: dict) -> str:
    """MUST match agents/neutralizer.py:_canonical_payload exactly."""
    return json.dumps(
        {"action_type": action_type, "target": target, "params": params},
        sort_keys=True,
        separators=(",", ":"),
    )


def _recompute_hash(action_type: str, target: str, params: dict) -> str:
    canonical = _canonical_payload(action_type, target, params)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_protected(target: str, cfg: dict) -> bool:
    """Independent re-implementation of the Neutralizer deny-list check."""
    protected = {str(t).lower() for t in cfg["execution"].get("protected_targets", [])}
    try:
        protected.add(socket.gethostname().lower())
    except OSError:
        pass
    return target.lower() in protected


def _get_infra_client():
    """
    Returns the active infra client based on config.execution.dry_run.
    Both branches expose identical method signatures:
        isolate_host(target, params) -> dict
        remove_host_isolation(target) -> dict
        lock_account(target, params) -> dict
        unlock_account(target) -> dict
        quarantine_process(target, params) -> dict
        terminate_process(target, params) -> dict
        restore_process(target) -> dict
        block_proxy_ip(target, params) -> dict
        unblock_proxy_ip(target) -> dict
    """
    cfg = load_config()["execution"]
    if cfg["dry_run"]:
        return stub_infra_api
    # Live execution path — routes to execution/real_infra_api.py which
    # performs actual OS-level actions (taskkill, netsh firewall rules).
    # Same function signatures as stub_infra_api, so all call sites are
    # unchanged. All upstream safety layers (hash, charset, allow-list)
    # still apply identically.
    from execution import real_infra_api
    return real_infra_api


def execute_action(state: UICRState) -> UICRState:
    """The Detached Python Execution Wrapper Node, as wired into the graph."""
    cfg = load_config()
    plan_dict = state.get("action_plan")
    if not plan_dict:
        logger.error("execute_action called with no action_plan in state — aborting.")
        return _record_failed_execution(state, target="unknown", action_type=ActionType.NO_ACTION,
                                         error="No action_plan present in UICR.")

    plan = ActionPlan(**plan_dict)  # re-validate from the dict, never trust the raw dict directly

    # --- Layer 1: hash re-verification -----------------------------------
    recomputed = _recompute_hash(plan.action_type.value, plan.target, plan.params)
    hash_ok = recomputed == plan.payload_hash
    if not hash_ok and cfg["security"]["hash_check"]:
        logger.critical(
            "PAYLOAD HASH MISMATCH for incident %s: stored=%s recomputed=%s. "
            "Aborting execution — possible state tampering.",
            state.get("incident_id"), plan.payload_hash, recomputed,
        )
        return _record_failed_execution(
            state, target=plan.target, action_type=plan.action_type,
            error="payload_hash verification failed; execution aborted.",
            hash_verified=False,
        )

    # --- Layer 2: independent charset re-check ---------------------------
    if not SAFE_TOKEN_PATTERN.match(plan.target):
        logger.critical(
            "Target '%s' failed wrapper-level charset re-check despite passing "
            "Pydantic validation upstream. Aborting.", plan.target[:32],
        )
        return _record_failed_execution(
            state, target=plan.target, action_type=plan.action_type,
            error="target failed independent charset allow-list re-check.",
            hash_verified=True,
        )

    # --- Layer 2b: protected-asset deny-list, re-checked independently ----
    if (
        plan.action_type != ActionType.NO_ACTION
        and cfg["security"]["deny_list"]
        and _is_protected(plan.target, cfg)
    ):
        logger.critical("Target '%s' is a protected asset. Aborting.", plan.target[:32])
        return _record_failed_execution(
            state, target=plan.target, action_type=plan.action_type,
            error="target is on the protected-asset deny-list; execution refused.",
            hash_verified=True,
        )

    # --- Layer 3: allow-list dispatch (no dynamic getattr) ----------------
    dry_run = cfg["execution"]["dry_run"]
    client = _get_infra_client()

    try:
        if plan.action_type == ActionType.ISOLATE_HOST:
            stub_response = client.isolate_host(plan.target, plan.params)
        elif plan.action_type == ActionType.LOCK_ACCOUNT:
            stub_response = client.lock_account(plan.target, plan.params)
        elif plan.action_type == ActionType.QUARANTINE_PROCESS:
            stub_response = client.quarantine_process(plan.target, plan.params)
        elif plan.action_type == ActionType.TERMINATE_PROCESS:
            stub_response = client.terminate_process(plan.target, plan.params)
        elif plan.action_type == ActionType.BLOCK_PROXY_IP:
            stub_response = client.block_proxy_ip(plan.target, plan.params)
        elif plan.action_type == ActionType.NO_ACTION:
            stub_response = {"detail": "NO_ACTION plan — nothing executed by design."}
        else:
            # Unreachable given the enum, but fail closed rather than silently no-op.
            raise ValueError(f"Unhandled action_type in dispatch: {plan.action_type}")

        result = ExecutionResult(
            action_type=plan.action_type,
            target=plan.target,
            dry_run=dry_run,
            success=stub_response.get("status") != "FAILED",
            hash_verified=hash_ok,
            stub_response=stub_response,
            error_message=(stub_response.get("stderr") or "OS command failed")[:512]
            if stub_response.get("status") == "FAILED" else None,
        )
    except Exception as e:  # noqa: BLE001 — this boundary must never crash the graph
        logger.exception("Execution failed for incident %s", state.get("incident_id"))
        result = ExecutionResult(
            action_type=plan.action_type,
            target=plan.target,
            dry_run=dry_run,
            success=False,
            hash_verified=True,
            stub_response={},
            error_message=str(e)[:512],
        )

    state["execution_result"] = result.model_dump(mode="json")
    state["current_phase"] = PipelinePhase.EXECUTING.value
    _write_exec_result_file(state, result, cfg)
    return state


def _record_failed_execution(
    state: UICRState,
    target: str,
    action_type: ActionType,
    error: str,
    hash_verified: bool = False,
) -> UICRState:
    cfg = load_config()
    result = ExecutionResult(
        action_type=action_type,
        target=target[:256],
        dry_run=cfg["execution"]["dry_run"],
        success=False,
        hash_verified=hash_verified,
        stub_response={},
        error_message=error[:512],
    )
    state["execution_result"] = result.model_dump(mode="json")
    state["current_phase"] = PipelinePhase.EXECUTING.value
    _write_exec_result_file(state, result, cfg)
    return state


def _write_exec_result_file(state: UICRState, result: ExecutionResult, cfg: dict) -> None:
    out_dir = Path(cfg["execution"]["exec_result_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    incident_id = state.get("incident_id", "unknown")
    out_path = out_dir / f"exec_result_{incident_id}.json"
    out_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
    logger.info("Wrote execution result to %s", out_path)


# ---------------------------------------------------------------------------
# Rollback contract — operator-facing reversal functions. Same dispatch
# discipline as execute_action: allow-list charset check, no dynamic calls.
# ---------------------------------------------------------------------------

def remove_host_isolation(target: str) -> dict:
    if not SAFE_TOKEN_PATTERN.match(target):
        raise ValueError("target failed charset allow-list; refusing rollback call.")
    client = _get_infra_client()
    return client.remove_host_isolation(target)


def unlock_account(target: str) -> dict:
    if not SAFE_TOKEN_PATTERN.match(target):
        raise ValueError("target failed charset allow-list; refusing rollback call.")
    client = _get_infra_client()
    return client.unlock_account(target)


def restore_process(target: str) -> dict:
    if not SAFE_TOKEN_PATTERN.match(target):
        raise ValueError("target failed charset allow-list; refusing rollback call.")
    client = _get_infra_client()
    return client.restore_process(target)


def unblock_proxy_ip(target: str) -> dict:
    if not SAFE_TOKEN_PATTERN.match(target):
        raise ValueError("target failed charset allow-list; refusing rollback call.")
    client = _get_infra_client()
    return client.unblock_proxy_ip(target)
