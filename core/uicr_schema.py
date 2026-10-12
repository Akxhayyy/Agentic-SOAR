"""
core/uicr_schema.py

The Unified Incident Context Record (UICR) is the single shared state object
passed by reference through every LangGraph node. It is intentionally split
into two layers:

1. Pydantic models (IOC, ActionPlan, ExecutionResult, etc.) — these are the
   STRICT validation gates. Anything entering the UICR from an untrusted
   boundary (the FastAPI ingestion endpoint, or LLM tool-call output) MUST
   pass through one of these models first. Field constraints here are the
   real defense, not the regex checks in the wrapper (those are a second,
   independent gate — defense in depth, not duplication for its own sake).

2. The UICRState TypedDict — the LangGraph-native state bag. LangGraph needs
   a TypedDict (or dataclass) for its state graph; we store *validated*
   Pydantic objects inside it as plain dict payloads (via .model_dump()) so
   the TypedDict stays JSON-serializable for the SqliteSaver checkpointer.

Design invariant: nothing downstream ever re-trusts a string. Every field
that could plausibly reach a shell, a regex, or a filesystem path is capped
in length and, where applicable, charset-restricted at the Pydantic layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, TypedDict
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations — closed vocabularies. The LLM may only ever select from these,
# never free-text a new value. This is enforced by Pydantic at parse time.
# ---------------------------------------------------------------------------

class AttackVector(str, Enum):
    NETWORK_INTRUSION = "NETWORK_INTRUSION"
    BRUTE_FORCE_AUTH = "BRUTE_FORCE_AUTH"
    MALWARE_EXECUTION = "MALWARE_EXECUTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    PROXY_ANOMALY = "PROXY_ANOMALY"
    UNKNOWN = "UNKNOWN"


class IOCType(str, Enum):
    IP_ADDRESS = "IP_ADDRESS"
    HOSTNAME = "HOSTNAME"
    USERNAME = "USERNAME"
    PROCESS_NAME = "PROCESS_NAME"
    FILE_HASH = "FILE_HASH"
    PORT = "PORT"


class ActionType(str, Enum):
    ISOLATE_HOST = "ISOLATE_HOST"
    LOCK_ACCOUNT = "LOCK_ACCOUNT"
    QUARANTINE_PROCESS = "QUARANTINE_PROCESS"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    BLOCK_PROXY_IP = "BLOCK_PROXY_IP"
    NO_ACTION = "NO_ACTION"


class HitlDecision(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    TIMEOUT = "TIMEOUT"


class ThreatStatus(str, Enum):
    OPEN = "OPEN"
    CONTAINED = "CONTAINED"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


class PipelinePhase(str, Enum):
    INGESTED = "INGESTED"
    TRIAGED = "TRIAGED"
    FORENSICS_PASS_1 = "FORENSICS_PASS_1"
    FORENSICS_PASS_2 = "FORENSICS_PASS_2"
    NEUTRALIZER_PLANNED = "NEUTRALIZER_PLANNED"
    AWAITING_HITL = "AWAITING_HITL"
    EXECUTING = "EXECUTING"
    COMPRESSING = "COMPRESSING"
    REPORTED = "REPORTED"
    FAILED = "FAILED"


# ---------------------------------------------------------------------------
# Hostile-boundary input model — this is what the FastAPI ingestion endpoint
# parses RAW logs into. Treat every field as adversarial input.
# ---------------------------------------------------------------------------

# Regex used at BOTH the Pydantic layer and re-checked independently inside
# execution/wrapper.py. Allow-list only: word chars, dot, colon, hyphen, @.
#
# ASCII ONLY. This used to be r"^[\w.:\-@]+$", but Python's \w matches any
# Unicode letter, so a Cyrillic homoglyph ("аdmin") passed the allow-list and
# could be locked/isolated in place of the real account (found by the red
# team, tests/redteam rt-21).
SAFE_TOKEN_PATTERN = r"^[A-Za-z0-9_.:\-@]+$"


class RawLogEntry(BaseModel):
    """Untrusted input boundary. FastAPI ingestion hands raw log lines here."""

    source: str = Field(..., max_length=64)
    log_type: str = Field(..., max_length=32)  # e.g. "AUTH", "PROXY", "NETFLOW"
    raw_text: str = Field(..., max_length=1024)
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("source", "log_type")
    @classmethod
    def _no_control_chars(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v):
            raise ValueError("control characters not permitted in metadata fields")
        return v


class IOC(BaseModel):
    """A single extracted Indicator of Compromise. Output of the Triage Agent."""

    ioc_type: IOCType
    value: str = Field(..., max_length=256)
    confidence: float = Field(..., ge=0.0, le=1.0)

    @field_validator("value")
    @classmethod
    def _value_charset(cls, v: str) -> str:
        import re
        if not re.match(SAFE_TOKEN_PATTERN, v):
            raise ValueError(
                f"IOC value '{v[:32]}...' contains disallowed characters; "
                f"must match {SAFE_TOKEN_PATTERN}"
            )
        return v


class TriageResult(BaseModel):
    """Output contract of the Triage Agent Node."""

    attack_vector: AttackVector
    discovered_layout: str = Field(..., max_length=256)
    iocs: list[IOC] = Field(default_factory=list, max_length=50)
    triage_summary: str = Field(..., max_length=512)
    triage_confidence: float = Field(..., ge=0.0, le=1.0)
    # ATT&CK technique IDs, filtered against config mitre.allowed_techniques
    # in agents/triage.py (invalid IDs are dropped, never fatal).
    mitre_techniques: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("discovered_layout")
    @classmethod
    def _layout_no_control_chars(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v):
            raise ValueError("control characters not permitted in discovered_layout")
        return v


class PlaybookMatch(BaseModel):
    """A single retrieved playbook chunk from ChromaDB, with its similarity score."""

    playbook_id: str = Field(..., max_length=128)
    chunk_text: str = Field(..., max_length=2048)
    similarity_score: float = Field(..., ge=0.0, le=1.0)


class ForensicsResult(BaseModel):
    """Output contract of the Forensics Agent Node (RAG)."""

    matches: list[PlaybookMatch] = Field(default_factory=list, max_length=8)
    pass_count: int = Field(..., ge=1, le=2)
    final_similarity_score: float = Field(..., ge=0.0, le=1.0)
    cleared_threshold: bool  # True only if final_similarity_score >= 0.70
    rag_timeline_notes: str = Field(default="", max_length=1024)
    best_playbook: str = Field(default="", max_length=128)   # source file of the top match
    rerank_reason: str = Field(default="", max_length=512)   # pass-2 LLM re-rank rationale
    # Tool-using investigator (agents/forensics.py). The agent's own confidence
    # is recorded but NEVER used for routing — final_similarity_score is the
    # embedding similarity of the playbook it chose.
    mode: str = Field(default="two_pass", max_length=16)     # "agent" | "two_pass"
    agent_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    agent_rationale: str = Field(default="", max_length=512)
    intel_hits: list[dict] = Field(default_factory=list, max_length=20)
    related_log_count: int = Field(default=0, ge=0)
    prior_incidents: list[str] = Field(default_factory=list, max_length=20)


class ActionPlan(BaseModel):
    """
    Output contract of the Neutralizer Agent Node.

    payload_hash is computed by the agent node over the canonical JSON
    serialization of (action_type, target, params) — NOT trusted as-is from
    the LLM. The execution wrapper independently RECOMPUTES this hash from
    the same fields before acting; a mismatch means the payload was tampered
    with in-memory between planning and execution, and execution is aborted.
    """

    action_type: ActionType
    target: str = Field(..., max_length=256)
    params: dict[str, str] = Field(default_factory=dict)
    justification: str = Field(..., max_length=512)
    payload_hash: str = Field(..., min_length=64, max_length=64)  # hex sha256
    # Outcome of the evidence-grounding check in agents/neutralizer.py. Not
    # part of the hashed payload — it describes the plan, it doesn't drive it.
    grounded: bool = True
    grounding_note: str = Field(default="", max_length=256)

    @field_validator("target")
    @classmethod
    def _target_charset(cls, v: str) -> str:
        import re
        if not re.match(SAFE_TOKEN_PATTERN, v):
            raise ValueError(f"target '{v[:32]}...' fails charset allow-list")
        return v

    @field_validator("payload_hash")
    @classmethod
    def _hash_is_hex(cls, v: str) -> str:
        import re
        if not re.match(r"^[0-9a-f]{64}$", v):
            raise ValueError("payload_hash must be a 64-char lowercase hex sha256 digest")
        return v


class ExecutionResult(BaseModel):
    """Output contract of the Detached Execution Wrapper Node."""

    action_type: ActionType
    target: str = Field(..., max_length=256)
    dry_run: bool
    success: bool
    hash_verified: bool  # did recomputed hash match ActionPlan.payload_hash?
    stub_response: dict = Field(default_factory=dict)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: Optional[str] = Field(default=None, max_length=512)


# ---------------------------------------------------------------------------
# The LangGraph-native state bag. Kept JSON-serializable: nested Pydantic
# objects are stored as plain dicts (model_dump(mode="json")) so SqliteSaver
# can pickle/serialize the checkpoint without custom encoders.
# ---------------------------------------------------------------------------

class UICRState(TypedDict, total=False):
    incident_id: str
    created_at: str  # ISO8601 string, not datetime — keeps TypedDict JSON-safe

    raw_logs: list[dict]            # list[RawLogEntry.model_dump()]
    triage: Optional[dict]          # TriageResult.model_dump()
    forensics: Optional[dict]       # ForensicsResult.model_dump()
    action_plan: Optional[dict]     # ActionPlan.model_dump()
    execution_result: Optional[dict]  # ExecutionResult.model_dump()

    hitl_decision: str              # HitlDecision value
    threat_status: str              # ThreatStatus value
    current_phase: str              # PipelinePhase value

    # Set by uicr_compress immediately before the Responder node runs.
    # Heavy fields (raw_logs text, full chunk_text in forensics.matches)
    # are stripped/truncated here to shield the KV cache on the final call.
    compressed: bool

    report_path: Optional[str]

    # Observability / lifecycle fields (all JSON-safe).
    group_key: Optional[str]          # ingestion grouping key, e.g. "ip:10.0.0.5"
    phase_history: list[dict]         # [{node, phase, started_at, ended_at, duration_s}]
    hitl_paused_at: Optional[str]     # ISO8601 wall-clock time the HITL gate paused
    hitl_operator_note: Optional[str]
    error: Optional[str]              # set when a node failed (current_phase=FAILED)
    rollback_result: Optional[dict]   # set by POST /api/incidents/{id}/rollback
    # Every forensics-agent step: [{step, tool, args, result_summary, duration_ms}]
    forensics_trace: list[dict]
    # {"first_seen": ISO, "last_seen": ISO} of the incident's log lines (for related-log lookups)
    time_window: Optional[dict]
    # log-store batch the incident's lines came from (independent-source corroboration)
    source_batch: Optional[str]
    # agents/corroboration.py assessment of the plan target: {signals, count, required, met, applies}
    corroboration: Optional[dict]
    # operator explicitly acknowledged approving an UNcorroborated destructive plan
    hitl_ack_uncorroborated: bool


def new_incident_state(group_key: str | None = None) -> UICRState:
    """Factory for a fresh UICR at graph entry. Called once per ingested incident."""
    return UICRState(
        incident_id=str(uuid4()),
        created_at=datetime.now(timezone.utc).isoformat(),
        raw_logs=[],
        triage=None,
        forensics=None,
        action_plan=None,
        execution_result=None,
        hitl_decision=HitlDecision.PENDING.value,
        threat_status=ThreatStatus.OPEN.value,
        current_phase=PipelinePhase.INGESTED.value,
        compressed=False,
        report_path=None,
        group_key=group_key,
        phase_history=[],
        hitl_paused_at=None,
        hitl_operator_note=None,
        error=None,
        rollback_result=None,
        forensics_trace=[],
        time_window=None,
        source_batch=None,
        corroboration=None,
        hitl_ack_uncorroborated=False,
    )
