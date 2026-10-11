"""Tool-using forensics agent: budget, trace, read-only tools, deterministic routing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.checkpointer import thread_config_for_incident
from core.uicr_schema import new_incident_state
from tests.conftest import BRUTE_FORCE_LOG


def _state(iocs=None, window=None):
    s = new_incident_state()
    s["raw_logs"] = [{"raw_text": BRUTE_FORCE_LOG, "log_type": "AUTH", "source": "t"}]
    s["triage"] = {
        "attack_vector": "BRUTE_FORCE_AUTH",
        "triage_summary": "Burst of failed logins then success.",
        "iocs": iocs if iocs is not None else [
            {"ioc_type": "IP_ADDRESS", "value": "10.0.4.17", "confidence": 1.0},
            {"ioc_type": "USERNAME", "value": "admin", "confidence": 1.0},
        ],
    }
    s["time_window"] = window
    return s


def _step(action, **args):
    return {"thought": f"try {action}", "action": action, "args": args}


# --------------------------------------------------------------------------- loop mechanics

def test_trace_records_every_step(fake_llm, fake_rag):
    from agents.forensics import forensics_node

    fake_llm.agent_steps = [
        _step("check_local_threat_intel", ioc="10.0.4.17"),
        _step("search_playbooks", query="password spraying"),
    ]
    out = forensics_node(_state())
    trace = out["forensics_trace"]
    assert [t["tool"] for t in trace] == ["check_local_threat_intel", "search_playbooks", "final"]
    for t in trace:
        assert {"step", "tool", "args", "result_summary", "duration_ms"} <= set(t)
    assert out["forensics"]["mode"] == "agent"
    assert out["forensics"]["best_playbook"] == "brute_force_auth.md"
    assert out["forensics"]["cleared_threshold"] is True
    assert out["forensics"]["agent_confidence"] == 0.9


def test_tool_budget_is_enforced(fake_llm, fake_rag, isolate_runtime):
    from agents.forensics import forensics_node

    fake_llm.agent_steps = [_step("search_playbooks", query=f"q{i}") for i in range(9)]
    out = forensics_node(_state())
    tools = [t["tool"] for t in out["forensics_trace"]]
    assert tools.count("search_playbooks") == 5 and tools[-1] == "final"
    last_schema = [c for c in fake_llm.calls if c["kind"] == "agent"][-1]["schema"]
    assert "anyOf" not in last_schema and last_schema["properties"]["action"]["const"] == "final"


def test_final_not_offered_before_min_tool_calls(fake_llm, fake_rag):
    from agents.forensics import forensics_node

    forensics_node(_state())
    schemas = [c["schema"] for c in fake_llm.calls if c["kind"] == "agent"]
    first_actions = {b["properties"]["action"]["const"] for b in schemas[0]["anyOf"]}
    second_actions = {b["properties"]["action"]["const"] for b in schemas[1]["anyOf"]}
    assert "final" not in first_actions and "final" in second_actions


def test_repeated_calls_are_served_from_cache(fake_llm, fake_rag):
    from agents.forensics import forensics_node

    fake_llm.agent_steps = [_step("search_playbooks", query="x"), _step("search_playbooks", query="x")]
    trace = forensics_node(_state())["forensics_trace"]
    assert "repeated call" in trace[1]["result_summary"]


def test_tool_args_restricted_to_extracted_iocs(fake_llm, fake_rag):
    # Even if a model (or injected text) names a foreign indicator, the tool refuses it.
    from agents.forensics import agent_step_schema, forensics_node

    fake_llm.agent_steps = [_step("check_local_threat_intel", ioc="8.8.8.8")]
    trace = forensics_node(_state())["forensics_trace"]
    assert trace[0]["result_summary"].startswith("tool error")
    schema = agent_step_schema(["10.0.4.17"], ["a.md"], allow_tools=True)
    ti = [b for b in schema["anyOf"] if b["properties"]["action"]["const"] == "check_local_threat_intel"][0]
    assert ti["properties"]["args"]["properties"]["ioc"]["enum"] == ["10.0.4.17"]


def test_no_ioc_tools_when_no_iocs(fake_llm, fake_rag):
    from agents.forensics import agent_step_schema

    actions = {b["properties"]["action"]["const"] for b in agent_step_schema([], ["a.md"], True)["anyOf"]}
    assert actions == {"search_playbooks", "final"}


# --------------------------------------------------------------------------- deterministic routing

def test_agent_confidence_never_drives_routing(fake_llm, fake_rag):
    # Agent picks a playbook retrieval never surfaced, with 0.99 confidence -> score 0, escalate.
    from agents.forensics import forensics_node

    fake_llm.agent_steps = []
    fake_llm.agent_final["args"].update(best_playbook="data_exfiltration.md", confidence=0.99)
    f = forensics_node(_state())["forensics"]
    assert f["agent_confidence"] == 0.99
    assert f["final_similarity_score"] == 0.0 and f["cleared_threshold"] is False
    assert "overrides" in f["rag_timeline_notes"]


def test_agent_override_uses_chosen_playbook_similarity(fake_llm, fake_rag):
    from agents.forensics import forensics_node

    fake_llm.agent_steps = []
    fake_llm.agent_final["args"]["best_playbook"] = "unknown_threat.md"  # retrieved at 0.62
    f = forensics_node(_state())["forensics"]
    assert f["final_similarity_score"] == pytest.approx(0.62)
    assert f["cleared_threshold"] is False
    assert f["matches"][0]["playbook_id"] == "unknown_threat.md"


def test_route_after_forensics_is_unchanged():
    from core.graph import route_after_forensics

    assert route_after_forensics({"forensics": {"cleared_threshold": True, "agent_confidence": 0.1}}) == "neutralizer"
    assert route_after_forensics({"forensics": {"cleared_threshold": False, "agent_confidence": 1.0}}) == "uicr_compress"


def test_agent_bug_falls_back_to_two_pass(fake_llm, fake_rag, monkeypatch):
    from agents import forensics, forensics_tools

    def boom(ctx, **kw):
        raise RuntimeError("tool bug")

    monkeypatch.setitem(forensics_tools.TOOLS, "check_local_threat_intel", boom)
    out = forensics.forensics_node(_state())
    assert out["forensics"]["mode"] == "two_pass"


def test_llm_outage_in_agent_fails_the_incident(graph, fake_llm):
    fake_llm.fail_on = "agent"
    s = _state()
    cfg = thread_config_for_incident(s["incident_id"])
    s.pop("triage")
    graph.invoke(s, cfg)
    v = graph.get_state(cfg).values
    assert v["current_phase"] == "FAILED" and v["error"].startswith("forensics")


# --------------------------------------------------------------------------- tools

def _ctx(values, window=None):
    from agents.forensics_tools import ToolContext

    return ToolContext(incident_id="me", ioc_values=values, time_window=window)


@pytest.mark.parametrize("value,hit", [
    ("203.0.113.5", True),                                   # inside TEST-NET-3 CIDR
    ("198.51.100.23", True),
    ("10.0.0.1", False),
    ("44D88612FEA8A8F36DE82E1278ABB02F", True),              # EICAR, case-insensitive
    ("mimikatz", True),                                      # process with or without .exe
    ("notepad.exe", False),
])
def test_threat_intel_matching(value, hit):
    from agents.forensics_tools import check_local_threat_intel

    result = check_local_threat_intel(_ctx([value]), value)
    assert bool(result.data["intel_hits"]) is hit
    assert ("MATCH" in result.summary) is hit


def test_related_logs_respect_time_window():
    from agents.forensics_tools import get_related_logs
    from ingestion.cheap_filter import parse_log_file
    from ingestion.log_store import add_lines

    t0 = datetime(2026, 6, 23, 22, 0, 0, tzinfo=timezone.utc)
    lines = parse_log_file("\n".join([
        f"{(t0 + timedelta(seconds=10)).isoformat()} failed login for user admin from 10.0.0.9",
        f"{(t0 + timedelta(seconds=40)).isoformat()} nmap scan detected from 10.0.0.9",
        f"{(t0 + timedelta(hours=3)).isoformat()} failed login for user admin from 10.0.0.9",
        f"{(t0 + timedelta(seconds=20)).isoformat()} unrelated event from 10.0.0.50",
    ]))
    add_lines("b1", lines)
    window = {"first_seen": t0.isoformat(), "last_seen": (t0 + timedelta(seconds=30)).isoformat()}
    r = get_related_logs(_ctx(["10.0.0.9"], window), "10.0.0.9", 300)
    assert r.data["related_count"] == 2 and r.data["suspicious"] == 2
    assert "scanning_tool" in r.data["reasons"]


def test_lookup_prior_incidents_finds_shared_iocs(graph, fake_llm, fake_rag):
    first = new_incident_state()
    first["raw_logs"] = [{"raw_text": BRUTE_FORCE_LOG, "log_type": "AUTH", "source": "t"}]
    graph.invoke(first, thread_config_for_incident(first["incident_id"]))

    fake_llm.agent_steps = [_step("lookup_prior_incidents", ioc="10.0.4.17")]
    second = new_incident_state()
    second["raw_logs"] = first["raw_logs"]
    cfg = thread_config_for_incident(second["incident_id"])
    graph.invoke(second, cfg)
    f = graph.get_state(cfg).values["forensics"]
    assert first["incident_id"] in f["prior_incidents"]


def test_tools_module_has_no_write_capabilities():
    import ast
    import inspect

    from agents import forensics_tools

    tree = ast.parse(inspect.getsource(forensics_tools))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    banned_modules = ("execution", "subprocess", "httpx", "shutil", "socket", "os")
    assert not [m for m in imported if m.split(".")[0] in banned_modules], imported
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not calls & {"write_text", "write_bytes", "unlink", "add_lines", "invoke", "update_state"}


def test_intel_hits_reach_the_neutralizer(fake_llm, fake_rag):
    from agents.forensics import forensics_node
    from agents.neutralizer import neutralizer_node

    s = _state(iocs=[{"ioc_type": "IP_ADDRESS", "value": "198.51.100.23", "confidence": 1.0},
                     {"ioc_type": "USERNAME", "value": "admin", "confidence": 1.0}])
    fake_llm.agent_steps = [_step("check_local_threat_intel", ioc="198.51.100.23")]
    s = forensics_node(s)
    assert s["forensics"]["intel_hits"][0]["ioc"] == "198.51.100.23"
    neutralizer_node(s)
    planner_prompt = [c for c in fake_llm.calls if c["kind"] == "planner"][0]["user_prompt"]
    assert "Credential-stuffing botnet node" in planner_prompt
