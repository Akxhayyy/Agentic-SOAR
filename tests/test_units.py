"""Unit tests — every Phase 1 bug fix has a regression test here. No Ollama needed."""

from __future__ import annotations

import json
import socket

import pytest
from pydantic import ValidationError

from core.uicr_schema import (
    IOC, ActionPlan, ActionType, PipelinePhase, RawLogEntry, ThreatStatus,
    TriageResult, new_incident_state,
)
from tests.conftest import BRUTE_FORCE_LOG


# --------------------------------------------------------------------------- schema

def test_ioc_charset_rejects_shell_metacharacters():
    with pytest.raises(ValidationError):
        IOC(ioc_type="USERNAME", value="admin; rm -rf /", confidence=0.5)


@pytest.mark.parametrize("value", ["аdmin", "ádmin", "admin​", "ｒｏｏｔ"])
def test_charset_is_ascii_only(value):
    # Regression (red team rt-21): \w admitted Unicode homoglyphs of real accounts.
    import re

    from execution.wrapper import SAFE_TOKEN_PATTERN as WRAPPER_PATTERN
    from core.uicr_schema import SAFE_TOKEN_PATTERN

    with pytest.raises(ValidationError):
        IOC(ioc_type="USERNAME", value=value, confidence=1.0)
    assert not re.match(SAFE_TOKEN_PATTERN, value) and not WRAPPER_PATTERN.match(value)


def test_raw_log_entry_caps_and_control_chars():
    with pytest.raises(ValidationError):
        RawLogEntry(source="a\x00b", log_type="AUTH", raw_text="x")
    with pytest.raises(ValidationError):
        RawLogEntry(source="s", log_type="AUTH", raw_text="x" * 1025)


def test_new_state_has_lifecycle_fields():
    s = new_incident_state(group_key="ip:1.2.3.4")
    assert s["group_key"] == "ip:1.2.3.4"
    assert s["phase_history"] == [] and s["error"] is None and s["hitl_paused_at"] is None
    assert PipelinePhase.FAILED.value == "FAILED"


def test_strict_schema_requires_defaulted_fields():
    # Regression: "iocs" had a default, so it wasn't required and the grammar let the model skip it.
    from agents.llm_client import strict_schema

    schema = strict_schema(TriageResult)
    assert "iocs" in schema["required"] and "mitre_techniques" in schema["required"]
    assert set(schema["$defs"]["IOC"]["required"]) == {"ioc_type", "value", "confidence"}


# --------------------------------------------------------------------------- llm client

def test_strip_fences_and_think_blocks():
    from agents.llm_client import parse_json_response, strip_fences

    assert strip_fences("```markdown\n# Title\n```") == "# Title"
    assert parse_json_response('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_response("<think>hmm</think>Sure: {\"a\": 2} done") == {"a": 2}


def test_num_ctx_hard_cap():
    from agents.llm_client import NUM_CTX_HARD_CAP, call_reasoning_model_ex

    with pytest.raises(ValueError):
        call_reasoning_model_ex("s", "u", "m", NUM_CTX_HARD_CAP + 1, 0.0)


def test_schema_and_num_predict_sent_to_ollama(monkeypatch):
    import agents.llm_client as llm

    sent = {}

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "{}"}, "eval_count": 10, "eval_duration": 1_000_000_000,
                    "prompt_eval_count": 5}

    class _Client:
        def __init__(self, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json):
            sent.update(json)
            return _Resp()

    monkeypatch.setattr(llm.httpx, "Client", _Client)
    monkeypatch.setattr(llm, "_model_capabilities", lambda m: frozenset({"thinking"}))
    resp = llm.call_reasoning_model_ex("s", "u", "qwen3:8b", 4096, 0.0, schema={"type": "object"}, max_tokens=99)
    assert sent["format"] == {"type": "object"}
    assert sent["options"]["num_predict"] == 99
    assert sent["think"] is False
    assert resp.tokens_per_s == pytest.approx(10.0)


# --------------------------------------------------------------------------- config

def test_config_paths_resolved_against_project_root():
    from core.graph_config import PROJECT_ROOT, _resolve

    assert _resolve("./data/x").startswith(str(PROJECT_ROOT))


def test_per_agent_model_override(isolate_runtime):
    from core.graph_config import reasoning_model_for

    isolate_runtime["models"]["reasoning"]["per_agent"] = {"report": "foundation-sec"}
    assert reasoning_model_for("report")["model"] == "foundation-sec"
    assert reasoning_model_for("triage")["model"] == isolate_runtime["models"]["reasoning"]["model"]


# --------------------------------------------------------------------------- triage

def _triage_state(text=BRUTE_FORCE_LOG):
    s = new_incident_state()
    s["raw_logs"] = [{"raw_text": text, "log_type": "AUTH", "source": "t"}]
    return s


def test_triage_happy_path_with_mitre(fake_llm):
    from agents.triage import triage_node

    out = triage_node(_triage_state())["triage"]
    assert out["attack_vector"] == "BRUTE_FORCE_AUTH"
    assert {"10.0.4.17", "admin"} <= {i["value"] for i in out["iocs"]}
    assert out["mitre_techniques"] == ["T1110", "T1078"]


def test_triage_parses_fenced_output(fake_llm):
    # Regression: ```json fences used to fail json.loads and degrade to UNKNOWN.
    from agents.triage import triage_node

    fake_llm.triage = "```json\n" + json.dumps(fake_llm.triage) + "\n```"
    assert triage_node(_triage_state())["triage"]["attack_vector"] == "BRUTE_FORCE_AUTH"


def test_triage_drops_bad_iocs_individually(fake_llm):
    from agents.triage import triage_node

    fake_llm.triage["iocs"] += [
        {"ioc_type": "USERNAME", "value": "bob; whoami", "confidence": 0.9},     # bad charset
        {"ioc_type": "HOSTNAME", "value": "dc01.corp.local", "confidence": 0.9},  # hallucinated
    ]
    out = triage_node(_triage_state())["triage"]
    values = {i["value"] for i in out["iocs"]}
    assert "dc01.corp.local" not in values and "10.0.4.17" in values
    assert any("not present in logs" in d for d in out["dropped_iocs"])
    assert out["attack_vector"] == "BRUTE_FORCE_AUTH"  # one bad IOC no longer sinks triage


def test_triage_filters_invalid_mitre_ids(fake_llm):
    from agents.triage import triage_node

    fake_llm.triage["mitre_techniques"] = ["T1110", "T9999", "not-an-id", "t1078", "T1110"]
    out = triage_node(_triage_state())["triage"]
    assert out["mitre_techniques"] == ["T1110", "T1078"]
    assert len(out["dropped_mitre"]) == 2


def test_triage_falls_back_to_unknown_after_two_failures(fake_llm):
    from agents.triage import triage_node

    fake_llm.triage = "this is not json"
    out = triage_node(_triage_state())["triage"]
    assert out["attack_vector"] == "UNKNOWN" and out["triage_confidence"] == 0.0
    assert fake_llm.count("triage") == 2


def test_regex_iocs_backfill_missed_indicators(fake_llm):
    from agents.triage import regex_iocs, triage_node

    found = {(i.ioc_type.value, i.value) for i in regex_iocs(
        "Rogue process PID:2024 user=svc-web src 999.1.1.1 dst 192.168.1.5 "
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")}
    assert ("PROCESS_NAME", "2024") in found and ("USERNAME", "svc-web") in found
    assert ("IP_ADDRESS", "192.168.1.5") in found and ("IP_ADDRESS", "999.1.1.1") not in found
    fake_llm.triage["iocs"] = []
    out = triage_node(_triage_state())["triage"]
    assert "10.0.4.17" in {i["value"] for i in out["iocs"]}


def test_triage_prompt_marks_logs_untrusted(fake_llm):
    from agents.triage import triage_node

    triage_node(_triage_state())
    call = fake_llm.calls[0]
    assert call["user_prompt"].startswith("<logs>")
    assert call["schema"]["properties"]["attack_vector"]


# --------------------------------------------------------------------------- neutralizer

IOCS = [
    {"ioc_type": "IP_ADDRESS", "value": "10.0.4.17", "confidence": 1.0},
    {"ioc_type": "USERNAME", "value": "admin", "confidence": 1.0},
    {"ioc_type": "PROCESS_NAME", "value": "2024", "confidence": 1.0},
]


def _planner_state():
    s = new_incident_state()
    s["triage"] = {"attack_vector": "BRUTE_FORCE_AUTH", "triage_summary": "x", "iocs": IOCS}
    s["forensics"] = {"final_similarity_score": 0.8, "best_playbook": "brute_force_auth.md",
                      "matches": [{"playbook_id": "brute_force_auth.md",
                                   "chunk_text": "## Containment Steps\nLock the account.",
                                   "similarity_score": 0.8}]}
    return s


def test_grounding_matrix():
    from agents.neutralizer import check_grounding

    assert check_grounding(ActionType.LOCK_ACCOUNT, "admin", IOCS)[0]
    assert check_grounding(ActionType.NO_ACTION, "none", IOCS)[0]
    ok, note = check_grounding(ActionType.LOCK_ACCOUNT, "user@example.com", IOCS)
    assert not ok and "does not appear" in note           # regression: invented target
    ok, note = check_grounding(ActionType.TERMINATE_PROCESS, "admin", IOCS)
    assert not ok and "cannot target" in note             # type mismatch
    ok, note = check_grounding(ActionType.BLOCK_PROXY_IP, "127.0.0.1",
                               IOCS + [{"ioc_type": "IP_ADDRESS", "value": "127.0.0.1", "confidence": 1}])
    assert not ok and "protected" in note                 # deny-list


def test_grounding_protects_local_hostname():
    from agents.neutralizer import check_grounding

    host = socket.gethostname()
    ok, _ = check_grounding(ActionType.ISOLATE_HOST, host, [{"ioc_type": "HOSTNAME", "value": host, "confidence": 1}])
    assert not ok


def test_plan_schema_encodes_action_target_matrix():
    from agents.neutralizer import plan_schema

    branches = {b["properties"]["action_type"]["const"]: b["properties"]["target"]["enum"]
                for b in plan_schema(IOCS)["anyOf"]}
    assert branches["LOCK_ACCOUNT"] == ["admin"]
    assert branches["TERMINATE_PROCESS"] == ["2024"]
    assert set(branches["ISOLATE_HOST"]) == {"10.0.4.17"}
    assert branches["NO_ACTION"] == ["none"]


def test_plan_schema_unconstrained_when_grounding_disabled(isolate_runtime):
    from agents.neutralizer import plan_schema

    isolate_runtime["security"]["grounding"] = False
    assert "anyOf" not in plan_schema(IOCS)


def test_neutralizer_grounded_plan_and_hash(fake_llm):
    from agents.neutralizer import neutralizer_node
    from execution.wrapper import _recompute_hash

    plan = neutralizer_node(_planner_state())["action_plan"]
    assert plan["action_type"] == "LOCK_ACCOUNT" and plan["target"] == "admin" and plan["grounded"]
    assert plan["payload_hash"] == _recompute_hash("LOCK_ACCOUNT", "admin", {})
    assert "Containment Steps" in fake_llm.calls[0]["user_prompt"]  # RAG text reaches the planner


def test_neutralizer_blocks_invented_target(fake_llm):
    from agents.neutralizer import neutralizer_node

    fake_llm.plan["target"] = "user@example.com"
    plan = neutralizer_node(_planner_state())["action_plan"]
    assert plan["action_type"] == "NO_ACTION" and plan["grounded"] is False


def test_neutralizer_coerces_param_types(fake_llm):
    # Regression: int param values tripped dict[str, str] and fell back to NO_ACTION.
    from agents.neutralizer import neutralizer_node

    fake_llm.plan["params"] = {"duration_minutes": 30, "notify": True}
    plan = neutralizer_node(_planner_state())["action_plan"]
    assert plan["params"] == {"duration_minutes": "30", "notify": "True"}


def test_neutralizer_none_target_becomes_no_action(fake_llm):
    from agents.neutralizer import neutralizer_node

    fake_llm.plan.update(action_type="ISOLATE_HOST", target="none")
    plan = neutralizer_node(_planner_state())["action_plan"]
    assert plan["action_type"] == "NO_ACTION" and plan["grounded"] is True


# --------------------------------------------------------------------------- execution wrapper

def _plan_state(action="LOCK_ACCOUNT", target="admin", tamper=False):
    from agents.neutralizer import _compute_payload_hash

    s = new_incident_state()
    h = _compute_payload_hash(action, target, {})
    s["action_plan"] = ActionPlan(action_type=action, target=target, params={}, justification="j",
                                  payload_hash=h).model_dump(mode="json")
    if tamper:
        s["action_plan"]["target"] = "root"
    return s


def test_wrapper_executes_verified_plan():
    from execution.wrapper import execute_action

    r = execute_action(_plan_state())["execution_result"]
    assert r["success"] and r["hash_verified"] and r["dry_run"]


def test_wrapper_aborts_on_hash_mismatch():
    from execution.wrapper import execute_action

    r = execute_action(_plan_state(tamper=True))["execution_result"]
    assert not r["success"] and not r["hash_verified"]


def test_wrapper_refuses_protected_target_independently():
    from execution.wrapper import execute_action

    r = execute_action(_plan_state("BLOCK_PROXY_IP", "127.0.0.1"))["execution_result"]
    assert not r["success"] and "deny-list" in r["error_message"]


def test_real_infra_terminate_by_pid_or_name(monkeypatch):
    # Regression: a process NAME was passed to taskkill /PID and always failed.
    import execution.real_infra_api as real

    seen = []

    class _R:
        returncode, stdout, stderr = 0, "ok", ""

    monkeypatch.setattr(real.subprocess, "run", lambda cmd, **kw: seen.append(cmd) or _R())
    real.terminate_process("8432", {})
    real.terminate_process("evil.exe", {})
    flat = [" ".join(c) for c in seen]
    assert ("/PID" in flat[0] or "kill -9 8432" in flat[0])
    assert ("/IM" in flat[1] or "pkill" in flat[1])


def test_rollback_functions_enforce_charset():
    from execution.wrapper import unlock_account

    with pytest.raises(ValueError):
        unlock_account("admin;whoami")
    assert unlock_account("admin")["status"] == "UNLOCKED"


# --------------------------------------------------------------------------- responder

@pytest.mark.parametrize("patch,expected", [
    ({"forensics": {"cleared_threshold": False}}, ThreatStatus.ESCALATED),
    ({"hitl_decision": "TIMEOUT"}, ThreatStatus.ESCALATED),
    ({"hitl_decision": "REJECTED"}, ThreatStatus.OPEN),
    ({"hitl_decision": "APPROVED", "execution_result": {"success": True, "action_type": "LOCK_ACCOUNT"}},
     ThreatStatus.CONTAINED),
    ({"hitl_decision": "APPROVED", "execution_result": {"success": True, "action_type": "NO_ACTION"}},
     ThreatStatus.CLOSED),
    ({"hitl_decision": "APPROVED", "execution_result": {"success": False}}, ThreatStatus.ESCALATED),
    ({"hitl_decision": "APPROVED", "action_plan": {"grounded": False},
      "execution_result": {"success": True, "action_type": "NO_ACTION"}}, ThreatStatus.ESCALATED),
    ({"error": "triage: boom"}, ThreatStatus.ESCALATED),
])
def test_threat_status_lifecycle(patch, expected):
    # Regression: CONTAINED/CLOSED were never assigned; forensics-miss stayed OPEN.
    from agents.responder import resolve_threat_status

    s = new_incident_state()
    s["forensics"] = {"cleared_threshold": True}
    s.update(patch)
    assert resolve_threat_status(s) == expected.value


def test_report_is_written_even_when_llm_is_down(fake_llm):
    from agents.responder import generate_report

    fake_llm.fail_on = "report"
    s = new_incident_state()
    s["forensics"] = {"cleared_threshold": False, "final_similarity_score": 0.4}
    out = generate_report(s)
    text = open(out["report_path"], encoding="utf-8").read()
    assert text.startswith("# Escalation Required")      # banner reflects the FINAL status
    assert out["threat_status"] == "ESCALATED" and "**ESCALATED**" in text
    assert "narrative unavailable" in text


def test_report_strips_llm_fences(fake_llm):
    from agents.responder import generate_report

    fake_llm.report = "```markdown\n### Executive Summary\nok\n```"
    s = new_incident_state()
    s.update(forensics={"cleared_threshold": True}, hitl_decision="APPROVED",
             execution_result={"success": True, "action_type": "LOCK_ACCOUNT"})
    text = open(generate_report(s)["report_path"], encoding="utf-8").read()
    assert "```" not in text and "### Executive Summary" in text


# --------------------------------------------------------------------------- ingestion

def test_mixed_timezone_timestamps_do_not_crash_grouping():
    # Regression: aware ISO-Z and naive timestamps raised TypeError in the sort.
    from ingestion.batch_processor import preview_log_file

    text = (
        "2026-06-23T22:00:01Z failed login for user root from 10.0.0.5\n"
        "2026-06-23 22:00:09 failed login for user root from 10.0.0.5\n"
        "Jun 23 22:00:15 sshd: failed login for user root from 10.0.0.5\n"
    )
    out = preview_log_file(text)
    assert out["suspicious_lines"] == 3
    assert all(l["timestamp"].endswith("+00:00") for l in out["lines"])
    assert len(out["groups"]) == 1


def test_ragged_csv_rows_are_tolerated():
    # Regression: DictReader's None key for extra cells crashed with AttributeError.
    from ingestion.cheap_filter import parse_log_file

    text = "timestamp,ip,username,message\n" \
           "2026-01-01T00:00:01Z,10.0.0.9,bob,failed login,EXTRA,CELLS\n" \
           "2026-01-01T00:00:02Z,10.0.0.9\n"
    lines = parse_log_file(text)
    assert len(lines) == 2 and lines[0].is_suspicious and lines[0].extracted_ip == "10.0.0.9"


def test_invalid_ip_octets_ignored():
    from ingestion.cheap_filter import parse_log_file

    line = parse_log_file("failed login from 999.300.1.1 then 10.1.1.1")[0]
    assert line.extracted_ip == "10.1.1.1"


def test_jsonl_keeps_structured_context():
    # Regression: only "message" reached triage, hiding the ip field from the LLM.
    from ingestion.cheap_filter import parse_log_file

    line = parse_log_file('{"time":"2026-06-23T22:20:05Z","ip":"10.0.0.99","message":"nmap scan detected"}')[0]
    assert "ip=10.0.0.99" in line.raw_text and line.is_suspicious


def test_preview_has_no_llm_calls(fake_llm):
    from ingestion.batch_processor import preview_log_file

    out = preview_log_file("hello world\nfailed login for user a from 1.2.3.4\n")
    assert out["total_lines"] == 2 and out["filtered_out_pct"] == 50.0
    assert fake_llm.calls == []


def test_success_login_absorbed_into_burst():
    from ingestion.batch_processor import preview_log_file

    text = "\n".join(
        [f"2026-06-23T22:00:0{i}Z failed login for user admin from 10.0.0.7" for i in range(5)]
        + ["2026-06-23T22:00:09Z successful login for user admin from 10.0.0.7"]
    )
    out = preview_log_file(text)
    assert out["groups"][0]["line_count"] == 6
