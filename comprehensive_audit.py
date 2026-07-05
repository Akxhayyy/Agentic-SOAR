"""
comprehensive_audit.py

Deep audit of the entire SOAR Capsule codebase — tests every component
in isolation (no Ollama/LLM calls required) to verify:
  1. Schema validation (Pydantic models, enums, constraints)
  2. Ingestion pipeline (cheap_filter parsing, CSV/JSON/syslog detection, grouping)
  3. Execution wrapper (hash verification, charset allow-list, dispatch)
  4. Responder (uicr_compress, report path logic)
  5. Graph wiring (conditional edge routing logic)
  6. Config loading
  7. Cross-component contract integrity (canonical hash shared between neutralizer & wrapper)
  8. Edge cases and adversarial inputs
"""

import hashlib
import json
import re
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PASS_COUNT = 0
FAIL_COUNT = 0
FAILURES = []


def check(label: str, condition: bool, detail: str = ""):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  [PASS] {label}")
    else:
        FAIL_COUNT += 1
        msg = f"  [FAIL] {label}" + (f" — {detail}" if detail else "")
        print(msg)
        FAILURES.append(msg)


# =====================================================================
# SECTION 1: Schema & Enum Validation
# =====================================================================
print("\n" + "="*70)
print("SECTION 1: Schema & Enum Validation")
print("="*70)

from core.uicr_schema import (
    ActionPlan, ActionType, AttackVector, ExecutionResult, ForensicsResult,
    HitlDecision, IOC, IOCType, PipelinePhase, PlaybookMatch, RawLogEntry,
    ThreatStatus, TriageResult, UICRState, new_incident_state, SAFE_TOKEN_PATTERN,
)
from pydantic import ValidationError

# 1.1 Enum completeness
check("ActionType has 6 values", len(ActionType) == 6)
check("AttackVector has 7 values", len(AttackVector) == 7)
check("HitlDecision has 4 values", len(HitlDecision) == 4)
check("ThreatStatus has 4 values", len(ThreatStatus) == 4)
check("PipelinePhase has 9 values", len(PipelinePhase) == 9)
check("IOCType has 6 values", len(IOCType) == 6)

# 1.2 RawLogEntry validation
entry = RawLogEntry(source="test-src", log_type="AUTH", raw_text="some log text")
check("RawLogEntry accepts valid input", entry.source == "test-src")

try:
    RawLogEntry(source="bad\x00src", log_type="AUTH", raw_text="test")
    check("RawLogEntry rejects control chars in source", False, "should have raised")
except ValidationError:
    check("RawLogEntry rejects control chars in source", True)

try:
    RawLogEntry(source="x" * 65, log_type="AUTH", raw_text="test")
    check("RawLogEntry enforces max_length on source", False)
except ValidationError:
    check("RawLogEntry enforces max_length on source", True)

try:
    RawLogEntry(source="ok", log_type="AUTH", raw_text="x" * 1025)
    check("RawLogEntry enforces max_length on raw_text", False)
except ValidationError:
    check("RawLogEntry enforces max_length on raw_text", True)

# 1.3 IOC charset validation
good_ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="192.168.1.1", confidence=0.9)
check("IOC accepts safe value", good_ioc.value == "192.168.1.1")

try:
    IOC(ioc_type=IOCType.IP_ADDRESS, value="192.168.1.1; rm -rf /", confidence=0.9)
    check("IOC rejects shell metacharacters", False)
except ValidationError:
    check("IOC rejects shell metacharacters", True)

try:
    IOC(ioc_type=IOCType.IP_ADDRESS, value="valid_ip", confidence=1.5)
    check("IOC rejects confidence > 1.0", False)
except ValidationError:
    check("IOC rejects confidence > 1.0", True)

# 1.4 TriageResult validation
tr = TriageResult(
    attack_vector=AttackVector.BRUTE_FORCE_AUTH,
    discovered_layout="syslog",
    iocs=[good_ioc],
    triage_summary="Brute force attempt detected",
    triage_confidence=0.85,
)
check("TriageResult accepts valid data", tr.attack_vector == AttackVector.BRUTE_FORCE_AUTH)

# 1.5 ActionPlan hash validation
try:
    ActionPlan(
        action_type=ActionType.LOCK_ACCOUNT,
        target="admin",
        params={},
        justification="test",
        payload_hash="not_a_real_hash",
    )
    check("ActionPlan rejects invalid hash format", False)
except ValidationError:
    check("ActionPlan rejects invalid hash format", True)

try:
    ActionPlan(
        action_type=ActionType.LOCK_ACCOUNT,
        target="admin user",  # space not allowed
        params={},
        justification="test",
        payload_hash="a" * 64,
    )
    check("ActionPlan rejects target with spaces", False)
except ValidationError:
    check("ActionPlan rejects target with spaces", True)

# 1.6 new_incident_state factory
state = new_incident_state()
check("new_incident_state sets incident_id", isinstance(state["incident_id"], str) and len(state["incident_id"]) > 0)
check("new_incident_state sets created_at", isinstance(state["created_at"], str))
check("new_incident_state sets PENDING hitl_decision", state["hitl_decision"] == "PENDING")
check("new_incident_state sets OPEN threat_status", state["threat_status"] == "OPEN")
check("new_incident_state sets INGESTED phase", state["current_phase"] == "INGESTED")
check("new_incident_state sets compressed=False", state["compressed"] is False)

# 1.7 ForensicsResult validation
fr = ForensicsResult(
    matches=[],
    pass_count=1,
    final_similarity_score=0.65,
    cleared_threshold=False,
    rag_timeline_notes="test notes",
)
check("ForensicsResult accepts valid data", fr.cleared_threshold is False)

try:
    ForensicsResult(matches=[], pass_count=3, final_similarity_score=0.5, cleared_threshold=False)
    check("ForensicsResult rejects pass_count > 2", False)
except ValidationError:
    check("ForensicsResult rejects pass_count > 2", True)

# 1.8 SAFE_TOKEN_PATTERN consistency check
pattern_in_schema = SAFE_TOKEN_PATTERN
wrapper_pattern = r"^[\w.:\-@]+$"
check("SAFE_TOKEN_PATTERN in schema matches expected", pattern_in_schema == wrapper_pattern)


# =====================================================================
# SECTION 2: Ingestion Pipeline (cheap_filter + grouping)
# =====================================================================
print("\n" + "="*70)
print("SECTION 2: Ingestion Pipeline (cheap_filter + grouping)")
print("="*70)

from ingestion.cheap_filter import parse_log_file, filter_suspicious, _parse_single_raw_line, _try_parse_timestamp, ParsedLogLine
from ingestion.grouping import group_suspicious_entries, IncidentGroup

# 2.1 Syslog format parsing
syslog_text = Path("data/samples/syslog_brute_force.txt").read_text()
syslog_lines = parse_log_file(syslog_text)
check(f"Syslog parsed {len(syslog_lines)} lines", len(syslog_lines) == 6)
suspicious_syslog = filter_suspicious(syslog_lines)
check(f"Syslog: {len(suspicious_syslog)} suspicious lines", len(suspicious_syslog) == 5,
      f"expected 5, got {len(suspicious_syslog)}")

# 2.2 CSV format parsing
csv_text = Path("data/samples/brute_force_success.csv").read_text()
csv_lines = parse_log_file(csv_text)
check(f"CSV parsed {len(csv_lines)} lines (data rows)", len(csv_lines) == 6)
suspicious_csv = filter_suspicious(csv_lines)
check(f"CSV: {len(suspicious_csv)} suspicious", len(suspicious_csv) == 5,
      f"expected 5, got {len(suspicious_csv)}")

# 2.3 JSON-Lines format parsing
json_text = Path("data/samples/network_scan.json").read_text()
json_lines = parse_log_file(json_text)
check(f"JSON parsed {len(json_lines)} lines", len(json_lines) == 4)
suspicious_json = filter_suspicious(json_lines)
check(f"JSON: {len(suspicious_json)} suspicious", len(suspicious_json) >= 2,
      f"got {len(suspicious_json)}")

# 2.4 CSV with IP extraction
for line in csv_lines:
    if line.extracted_ip:
        check("CSV IP extraction works", line.extracted_ip == "192.168.1.100")
        break
else:
    check("CSV IP extraction works", False, "no IP extracted")

# 2.5 CSV with username extraction
for line in csv_lines:
    if line.extracted_user:
        check("CSV username extraction works", line.extracted_user == "administrator")
        break
else:
    check("CSV username extraction works", False, "no user extracted")

# 2.6 Success login detection
success_lines = [l for l in syslog_lines if l.is_success_login]
check("Syslog detects success login line", len(success_lines) == 1)

csv_success = [l for l in csv_lines if l.is_success_login]
check("CSV detects success login line", len(csv_success) == 1)

# 2.7 Grouping by IP
groups_csv = group_suspicious_entries(suspicious_csv, all_lines=csv_lines)
check(f"CSV groups: {len(groups_csv)} group(s)", len(groups_csv) == 1)
if groups_csv:
    check("CSV group key is ip-based", groups_csv[0].group_key.startswith("ip:"))
    # Check success login absorption
    has_success = any(l.is_success_login for l in groups_csv[0].lines)
    check("CSV group absorbed success login context", has_success)

# 2.8 Grouping with syslog
groups_syslog = group_suspicious_entries(suspicious_syslog, all_lines=syslog_lines)
check(f"Syslog groups: {len(groups_syslog)} group(s)", len(groups_syslog) >= 1)

# 2.9 Empty input handling
empty_lines = parse_log_file("")
check("Empty input returns empty list", len(empty_lines) == 0)

# 2.10 Timestamp parsing
ts1 = _try_parse_timestamp("2026-06-25T00:30:01Z")
check("ISO timestamp parsing works", ts1 is not None)

ts2 = _try_parse_timestamp("Jun 23 22:10:01")
check("Syslog timestamp parsing works", ts2 is not None)

# 2.11 Ungrouped lines (no IP/user) become single-line groups
lone_line = ParsedLogLine(
    raw_text="malware detected in memory",
    log_type="GENERIC",
    source="batch_upload",
    timestamp=None,
    extracted_ip=None,
    extracted_user=None,
    is_suspicious=True,
    match_reason="explicit_threat_keyword",
)
lone_groups = group_suspicious_entries([lone_line])
check("Ungrouped line gets single:N key", len(lone_groups) == 1 and lone_groups[0].group_key.startswith("single:"))

# 2.12 E2E verify CSV
e2e_text = Path("data/samples/e2e_verify.csv").read_text()
e2e_lines = parse_log_file(e2e_text)
e2e_suspicious = filter_suspicious(e2e_lines)
e2e_groups = group_suspicious_entries(e2e_suspicious, all_lines=e2e_lines)
check(f"E2E CSV: {len(e2e_lines)} lines, {len(e2e_suspicious)} suspicious, {len(e2e_groups)} group(s)",
      len(e2e_lines) == 6 and len(e2e_groups) >= 1)


# =====================================================================
# SECTION 3: Execution Wrapper Integrity
# =====================================================================
print("\n" + "="*70)
print("SECTION 3: Execution Wrapper Integrity")
print("="*70)

from agents.neutralizer import _canonical_payload as neutralizer_canonical, _compute_payload_hash
from execution.wrapper import _canonical_payload as wrapper_canonical, _recompute_hash, SAFE_TOKEN_PATTERN as WRAPPER_SAFE_PATTERN

# 3.1 Canonical payload consistency
test_action = "LOCK_ACCOUNT"
test_target = "admin"
test_params = {"reason": "brute_force"}

neutralizer_json = neutralizer_canonical(test_action, test_target, test_params)
wrapper_json = wrapper_canonical(test_action, test_target, test_params)
check("Canonical payload: neutralizer == wrapper", neutralizer_json == wrapper_json,
      f"\nneutralizer: {neutralizer_json}\nwrapper:     {wrapper_json}")

# 3.2 Hash consistency
h1 = _compute_payload_hash(test_action, test_target, test_params)
h2 = _recompute_hash(test_action, test_target, test_params)
check("Hash computation: neutralizer == wrapper", h1 == h2)

# 3.3 Hash is valid sha256 hex
check("Hash is 64-char hex", len(h1) == 64 and all(c in "0123456789abcdef" for c in h1))

# 3.4 Hash changes when payload changes
h3 = _compute_payload_hash("ISOLATE_HOST", test_target, test_params)
check("Different action_type -> different hash", h1 != h3)

h4 = _compute_payload_hash(test_action, "other_target", test_params)
check("Different target -> different hash", h1 != h4)

# 3.5 SAFE_TOKEN_PATTERN re-declaration
check("Wrapper SAFE_TOKEN_PATTERN matches schema pattern",
      WRAPPER_SAFE_PATTERN.pattern == r"^[\w.:\-@]+$")

# 3.6 Stub infra API function signatures match
from execution import stub_infra_api, real_infra_api
import inspect

stub_funcs = {
    "isolate_host", "remove_host_isolation", "lock_account", "unlock_account",
    "quarantine_process", "terminate_process", "restore_process",
    "block_proxy_ip", "unblock_proxy_ip",
}
for fn_name in stub_funcs:
    stub_fn = getattr(stub_infra_api, fn_name, None)
    real_fn = getattr(real_infra_api, fn_name, None)
    check(f"Function {fn_name} exists in both APIs",
          stub_fn is not None and real_fn is not None)
    if stub_fn and real_fn:
        stub_sig = inspect.signature(stub_fn)
        real_sig = inspect.signature(real_fn)
        check(f"Function {fn_name} signatures match",
              list(stub_sig.parameters.keys()) == list(real_sig.parameters.keys()),
              f"stub={list(stub_sig.parameters.keys())} real={list(real_sig.parameters.keys())}")

# 3.7 Stub functions return correct structures
r = stub_infra_api.isolate_host("test-host", {"vlan": "quarantine"})
check("isolate_host returns simulated=True", r["simulated"] is True)
check("isolate_host returns status=ISOLATED", r["status"] == "ISOLATED")
check("isolate_host returns timestamp", "timestamp" in r)

r = stub_infra_api.lock_account("admin", {})
check("lock_account returns status=LOCKED", r["status"] == "LOCKED")

# 3.8 Rollback state tracking
stub_infra_api._isolated_hosts.clear()
stub_infra_api.isolate_host("hostA", {})
r_rollback = stub_infra_api.remove_host_isolation("hostA")
check("Rollback tracks was_isolated=True", r_rollback["was_isolated"] is True)
r_rollback2 = stub_infra_api.remove_host_isolation("hostA")
check("Double rollback reports was_isolated=False", r_rollback2["was_isolated"] is False)

# 3.9 Execute action with valid plan (dry_run=True)
from execution.wrapper import execute_action

payload_hash = _compute_payload_hash("NO_ACTION", "none", {})
test_state = new_incident_state()
test_state["action_plan"] = ActionPlan(
    action_type=ActionType.NO_ACTION,
    target="none",
    params={},
    justification="test",
    payload_hash=payload_hash,
).model_dump(mode="json")

result_state = execute_action(test_state)
exec_result = result_state.get("execution_result")
check("execute_action succeeds with NO_ACTION plan", exec_result is not None and exec_result["success"] is True)
check("execute_action sets hash_verified=True", exec_result is not None and exec_result["hash_verified"] is True)

# 3.10 Execute action with tampered hash
tampered_state = new_incident_state()
tampered_state["action_plan"] = {
    "action_type": "LOCK_ACCOUNT",
    "target": "admin",
    "params": {},
    "justification": "test",
    "payload_hash": "0" * 64,  # wrong hash
}
result_tampered = execute_action(tampered_state)
exec_tampered = result_tampered.get("execution_result")
check("execute_action detects tampered hash",
      exec_tampered is not None and exec_tampered["success"] is False and exec_tampered["hash_verified"] is False)


# =====================================================================
# SECTION 4: Responder (uicr_compress + report logic)
# =====================================================================
print("\n" + "="*70)
print("SECTION 4: Responder (uicr_compress + report logic)")
print("="*70)

from agents.responder import uicr_compress, _is_escalation_path, _build_report_context, RAW_LOG_TRUNCATE_CHARS, CHUNK_TEXT_TRUNCATE_CHARS

# 4.1 uicr_compress truncates long raw_text
state_compress = new_incident_state()
state_compress["raw_logs"] = [
    {"raw_text": "A" * 500, "log_type": "AUTH", "source": "test"},
]
state_compress["forensics"] = {
    "matches": [
        {"playbook_id": "test_pb", "chunk_text": "B" * 500, "similarity_score": 0.8},
    ],
    "pass_count": 1,
    "final_similarity_score": 0.8,
    "cleared_threshold": True,
    "rag_timeline_notes": "test",
}
compressed = uicr_compress(state_compress)
check("uicr_compress sets compressed=True", compressed["compressed"] is True)
check("uicr_compress truncates raw_text",
      len(compressed["raw_logs"][0]["raw_text"]) < 500)
check("uicr_compress truncates chunk_text",
      len(compressed["forensics"]["matches"][0]["chunk_text"]) < 500)
check("uicr_compress preserves short raw_text",
      "...[truncated by uicr_compress]" in compressed["raw_logs"][0]["raw_text"])

# 4.2 uicr_compress with already-short text (no truncation needed)
state_short = new_incident_state()
state_short["raw_logs"] = [
    {"raw_text": "short log", "log_type": "AUTH", "source": "test"},
]
compressed_short = uicr_compress(state_short)
check("uicr_compress preserves short raw_text without marker",
      compressed_short["raw_logs"][0]["raw_text"] == "short log")

# 4.3 Escalation path detection
check("Escalation: cleared_threshold=False",
      _is_escalation_path({"forensics": {"cleared_threshold": False}, "hitl_decision": "PENDING"}) is True)
check("Escalation: TIMEOUT decision",
      _is_escalation_path({"forensics": {"cleared_threshold": True}, "hitl_decision": "TIMEOUT"}) is True)
check("Escalation: REJECTED decision",
      _is_escalation_path({"forensics": {"cleared_threshold": True}, "hitl_decision": "REJECTED"}) is True)
check("Non-escalation: APPROVED with cleared",
      _is_escalation_path({"forensics": {"cleared_threshold": True}, "hitl_decision": "APPROVED"}) is False)
check("Non-escalation: PENDING with cleared",
      _is_escalation_path({"forensics": {"cleared_threshold": True}, "hitl_decision": "PENDING"}) is False)

# 4.4 Report context builder
ctx_state = new_incident_state()
ctx_state["triage"] = {"attack_vector": "BRUTE_FORCE_AUTH", "triage_summary": "test"}
ctx = _build_report_context(ctx_state)
parsed_ctx = json.loads(ctx)
check("Report context includes incident_id", "incident_id" in parsed_ctx)
check("Report context includes triage", "triage" in parsed_ctx)


# =====================================================================
# SECTION 5: Graph Wiring & Conditional Edges
# =====================================================================
print("\n" + "="*70)
print("SECTION 5: Graph Wiring & Conditional Edges")
print("="*70)

from core.graph import route_after_forensics, route_after_hitl

# 5.1 route_after_forensics
check("Forensics routes to neutralizer when cleared",
      route_after_forensics({"forensics": {"cleared_threshold": True}}) == "neutralizer")
check("Forensics routes to uicr_compress when NOT cleared",
      route_after_forensics({"forensics": {"cleared_threshold": False}}) == "uicr_compress")
check("Forensics routes to uicr_compress when forensics is None",
      route_after_forensics({"forensics": None}) == "uicr_compress")
check("Forensics routes to uicr_compress when forensics missing",
      route_after_forensics({}) == "uicr_compress")

# 5.2 route_after_hitl
check("HITL APPROVED routes to execute_action",
      route_after_hitl({"hitl_decision": HitlDecision.APPROVED.value}) == "execute_action")
check("HITL REJECTED routes to uicr_compress",
      route_after_hitl({"hitl_decision": HitlDecision.REJECTED.value}) == "uicr_compress")
check("HITL TIMEOUT routes to uicr_compress",
      route_after_hitl({"hitl_decision": HitlDecision.TIMEOUT.value}) == "uicr_compress")
check("HITL None routes to uicr_compress",
      route_after_hitl({"hitl_decision": None}) == "uicr_compress")


# =====================================================================
# SECTION 6: Config Loading
# =====================================================================
print("\n" + "="*70)
print("SECTION 6: Config Loading")
print("="*70)

from core.graph_config import load_config, CONFIG_PATH

check("Config file exists", CONFIG_PATH.exists())

cfg = load_config()
check("Config has 'execution' section", "execution" in cfg)
check("Config has 'hitl' section", "hitl" in cfg)
check("Config has 'forensics' section", "forensics" in cfg)
check("Config has 'models' section", "models" in cfg)
check("Config has 'dashboard' section", "dashboard" in cfg)

# 6.1 Specific values
check("Hard threshold is 0.70", cfg["forensics"]["similarity_hard_threshold"] == 0.70)
check("HITL timeout is 300s", cfg["hitl"]["timeout_seconds"] == 300)
check("Pass 1 top_k is 5", cfg["forensics"]["pass_1"]["top_k"] == 5)
check("Pass 2 top_k is 8", cfg["forensics"]["pass_2"]["top_k"] == 8)
check("Pass 2 similarity_floor is 0.35", cfg["forensics"]["pass_2"]["similarity_floor"] == 0.35)
check("Reasoning model is qwen2.5:7b", "qwen2.5" in cfg["models"]["reasoning"]["model"])
check("Embedding model is nomic-embed-text", cfg["models"]["embedding"]["model"] == "nomic-embed-text")
check("num_ctx is 4096", cfg["models"]["reasoning"]["num_ctx"] == 4096)
check("temperature is 0.0", cfg["models"]["reasoning"]["temperature"] == 0.0)

# 6.2 Platform-specific path concern
check("exec_result_dir is configured", "exec_result_dir" in cfg["execution"])
check("checkpointer_db_path is configured", "checkpointer_db_path" in cfg["hitl"])

# FLAG: Unix paths in config on Windows
if sys.platform.startswith("win"):
    exec_dir = cfg["execution"]["exec_result_dir"]
    cp_path = cfg["hitl"]["checkpointer_db_path"]
    if exec_dir.startswith("/"):
        print(f"  [WARN] exec_result_dir='{exec_dir}' is a Unix path (running on Windows)")
    if cp_path.startswith("/"):
        print(f"  [WARN] checkpointer_db_path='{cp_path}' is a Unix path (running on Windows)")


# =====================================================================
# SECTION 7: Playbook Files Integrity
# =====================================================================
print("\n" + "="*70)
print("SECTION 7: Playbook Files Integrity")
print("="*70)

playbook_dir = Path("config/playbooks")
expected_playbooks = {
    "brute_force_auth.md", "data_exfiltration.md", "malware_execution.md",
    "network_intrusion.md", "privilege_escalation.md", "proxy_anomaly.md",
    "unknown_threat.md",
}
actual_playbooks = {p.name for p in playbook_dir.glob("*.md")}
check("All 7 playbooks present", actual_playbooks == expected_playbooks,
      f"missing: {expected_playbooks - actual_playbooks}, extra: {actual_playbooks - expected_playbooks}")

for pb in sorted(playbook_dir.glob("*.md")):
    content = pb.read_text(encoding="utf-8")
    check(f"Playbook {pb.name} is non-empty", len(content.strip()) > 100,
          f"only {len(content.strip())} chars")


# =====================================================================
# SECTION 8: LLM Client Contract Checks (no actual calls)
# =====================================================================
print("\n" + "="*70)
print("SECTION 8: LLM Client Contract Checks")
print("="*70)

from agents.llm_client import call_reasoning_model, call_embedding_model, OLLAMA_BASE_URL

check("OLLAMA_BASE_URL is localhost", "localhost" in OLLAMA_BASE_URL or "127.0.0.1" in OLLAMA_BASE_URL)

# 8.1 num_ctx guard
try:
    call_reasoning_model("sys", "user", "model", num_ctx=8192, temperature=0.0, timeout_s=0.001)
    check("call_reasoning_model rejects num_ctx > 4096", False)
except ValueError as e:
    check("call_reasoning_model rejects num_ctx > 4096", "4096" in str(e))
except Exception:
    # Connection error expected since Ollama may not be running, but ValueError should come first
    check("call_reasoning_model rejects num_ctx > 4096", False, "got connection error before ValueError")


# =====================================================================
# SECTION 9: Edge Cases & Adversarial Inputs
# =====================================================================
print("\n" + "="*70)
print("SECTION 9: Edge Cases & Adversarial Inputs")
print("="*70)

# 9.1 Adversarial log injection
adversarial_log = "[AUTH] 192.168.1.1; DROP TABLE users; --"
lines = parse_log_file(adversarial_log)
check("SQL injection in log text is parsed safely", len(lines) == 1)

# 9.2 Unicode in logs
unicode_log = "[AUTH] Failed login from user möbius@domain.com 192.168.1.1"
ulines = parse_log_file(unicode_log)
check("Unicode in logs parses without crash", len(ulines) == 1)

# 9.3 Extremely long single line
long_line = "[AUTH] " + "A" * 5000 + " failed login"
long_lines = parse_log_file(long_line)
check("Very long line parses without crash", len(long_lines) == 1)
check("Long line raw_text capped at 1024", len(long_lines[0].raw_text) <= 1024)

# 9.4 ActionPlan target with path traversal
try:
    ActionPlan(
        action_type=ActionType.ISOLATE_HOST,
        target="../../etc/passwd",
        params={},
        justification="test",
        payload_hash="a" * 64,
    )
    check("ActionPlan rejects path traversal in target", False, "should have raised due to / chars")
except ValidationError:
    check("ActionPlan rejects path traversal in target", True)

# 9.5 Empty state through execute_action
empty_state = new_incident_state()
result_empty = execute_action(empty_state)
check("execute_action handles missing action_plan gracefully",
      result_empty["execution_result"]["success"] is False)

# 9.6 Delimiter handling
semicolon_text = Path("data/samples/semicolon_brute_force.txt").read_text()
sc_lines = parse_log_file(semicolon_text)
check(f"Semicolon file parses ({len(sc_lines)} lines)", len(sc_lines) > 0)


# =====================================================================
# SECTION 10: Cross-Module Import Verification
# =====================================================================
print("\n" + "="*70)
print("SECTION 10: Cross-Module Import Verification")
print("="*70)

# Verify all inter-module imports work
imports_ok = True
try:
    from core.uicr_schema import UICRState, new_incident_state
    from core.graph_config import load_config
    from core.checkpointer import get_checkpointer, thread_config_for_incident
    from core.graph import build_graph, get_compiled_graph, route_after_forensics, route_after_hitl, hitl_gate_node
    from agents.triage import triage_node, TRIAGE_SYSTEM_PROMPT
    from agents.forensics import forensics_node
    from agents.neutralizer import neutralizer_node, NEUTRALIZER_SYSTEM_PROMPT
    from agents.responder import uicr_compress, generate_report
    from agents.llm_client import call_reasoning_model, call_embedding_model
    from execution.wrapper import execute_action, remove_host_isolation, unlock_account, restore_process, unblock_proxy_ip
    from execution.stub_infra_api import isolate_host, lock_account
    from ingestion.batch_processor import process_log_file
    from ingestion.cheap_filter import parse_log_file, filter_suspicious
    from ingestion.grouping import group_suspicious_entries, IncidentGroup
    from rag.chroma_store import query_playbooks, ensure_cosine_collection
    from rag.ingest_playbooks import ingest_all, _chunk_text
except ImportError as e:
    imports_ok = False
    check(f"All cross-module imports succeed", False, str(e))

if imports_ok:
    check("All cross-module imports succeed", True)

# 10.1 Thread config generation
tc = thread_config_for_incident("test-123")
check("thread_config_for_incident returns correct structure",
      tc == {"configurable": {"thread_id": "test-123"}})

# 10.2 Playbook chunking
chunks = _chunk_text("Hello world " * 200)
check(f"_chunk_text produces multiple chunks for long text", len(chunks) > 1)
chunks_short = _chunk_text("Short text")
check("_chunk_text produces single chunk for short text", len(chunks_short) == 1)


# =====================================================================
# SUMMARY
# =====================================================================
print("\n" + "="*70)
print(f"AUDIT COMPLETE: {PASS_COUNT} passed, {FAIL_COUNT} failed")
print("="*70)

if FAILURES:
    print("\nFAILURES:")
    for f in FAILURES:
        print(f)
    sys.exit(1)
else:
    print("\n[OK] ALL CHECKS PASSED - No bugs or contract violations detected.")
    sys.exit(0)
