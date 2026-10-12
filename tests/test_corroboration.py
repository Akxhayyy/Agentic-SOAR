"""Corroboration: independent-evidence signals for destructive plans (answer to evidence poisoning)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.uicr_schema import ActionType, new_incident_state
from tests.conftest import BRUTE_FORCE_LOG


@pytest.fixture(autouse=True)
def corroboration_on(isolate_runtime):
    isolate_runtime["security"]["corroboration"] = {"enabled": True, "min_signals": 2, "window_s": 3600}


def _state(lines, types=None, batch="b-own"):
    s = new_incident_state()
    s["raw_logs"] = [{"raw_text": l, "log_type": (types or ["AUTH"] * len(lines))[i], "source": "t"}
                     for i, l in enumerate(lines)]
    s["source_batch"] = batch
    s["time_window"] = {"first_seen": "2026-06-23T10:00:00+00:00", "last_seen": "2026-06-23T10:01:00+00:00"}
    return s


def kinds(result):
    return {s["kind"] for s in result["signals"]}


def test_single_source_is_not_corroborated():
    from agents.corroboration import assess

    r = assess(_state(["failed login for user bob from 10.0.0.9"]), "LOCK_ACCOUNT", "bob")
    assert r["applies"] and not r["met"] and kinds(r) == {"incident_evidence"}


def test_no_action_never_needs_corroboration():
    from agents.corroboration import assess

    r = assess(_state(["x"]), "NO_ACTION", "none")
    assert not r["applies"] and r["met"]


def test_second_telemetry_type_corroborates():
    from agents.corroboration import assess

    s = _state(["failed login for user bob", "EDR: bob spawned powershell"], types=["AUTH", "EDR"])
    r = assess(s, "LOCK_ACCOUNT", "bob")
    assert r["met"] and "second_telemetry_type" in kinds(r)


def test_independent_feed_corroborates_but_own_batch_does_not():
    from agents.corroboration import assess
    from ingestion.cheap_filter import parse_log_file
    from ingestion.log_store import add_lines

    line = "2026-06-23T10:00:30Z failed login for user bob from 10.0.0.9"
    add_lines("b-own", parse_log_file(line))
    assert not assess(_state([line]), "LOCK_ACCOUNT", "bob")["met"]      # same feed: no signal
    add_lines("b-vpn", parse_log_file("2026-06-23T10:00:40Z vpn failed login for user bob from 10.0.0.9"))
    r = assess(_state([line]), "LOCK_ACCOUNT", "bob")
    assert r["met"] and "independent_source" in kinds(r)


def test_threat_intel_corroborates():
    from agents.corroboration import assess

    r = assess(_state(["CONNECT from 198.51.100.23"]), "BLOCK_PROXY_IP", "198.51.100.23")
    assert r["met"] and "threat_intel" in kinds(r)


def test_wrapper_refuses_uncorroborated_without_ack_and_runs_with_ack():
    from agents.neutralizer import sealed_plan
    from execution.wrapper import execute_action

    def plan_state(ack):
        s = _state(["failed login for user bob from 10.0.0.9"])
        s["action_plan"] = sealed_plan(s["incident_id"], ActionType.LOCK_ACCOUNT, "bob", {}, "j").model_dump(mode="json")
        s["hitl_ack_uncorroborated"] = ack
        return s

    refused = execute_action(plan_state(False))["execution_result"]
    assert not refused["success"] and "uncorroborated" in refused["error_message"]
    assert execute_action(plan_state(True))["execution_result"]["success"]


def test_wrapper_ignores_a_tampered_stored_assessment():
    # The stored corroboration result is not trusted: the wrapper re-assesses.
    from agents.neutralizer import sealed_plan
    from execution.wrapper import execute_action

    s = _state(["failed login for user bob"])
    s["action_plan"] = sealed_plan(s["incident_id"], ActionType.LOCK_ACCOUNT, "bob", {}, "j").model_dump(mode="json")
    s["corroboration"] = {"applies": True, "met": True, "count": 5, "required": 2, "signals": []}
    assert not execute_action(s)["execution_result"]["success"]


def test_api_requires_acknowledgement_for_uncorroborated_approval(graph, monkeypatch):
    monkeypatch.setattr("agents.llm_client.ollama_status",
                        lambda models: {"online": True, "pulled": models, "missing": [], "loaded": []})
    import main

    main.TIMEOUT_TASKS.clear()
    with TestClient(main.app) as c:
        iid = c.post("/api/ingest", json={"source": "gw", "log_type": "AUTH", "raw_text": BRUTE_FORCE_LOG}).json()["incident_id"]
        corr = c.get(f"/api/incidents/{iid}").json()["state"]["corroboration"]
        assert corr["applies"] and not corr["met"]
        r = c.post(f"/api/incidents/{iid}/decision", json={"decision": "APPROVED"})
        assert r.status_code == 409 and "acknowledge_uncorroborated" in r.json()["detail"]
        assert c.post(f"/api/incidents/{iid}/decision", json={"decision": "REJECTED"}).status_code == 200


def test_api_acknowledged_approval_executes_and_is_audited(graph, monkeypatch):
    monkeypatch.setattr("agents.llm_client.ollama_status",
                        lambda models: {"online": True, "pulled": models, "missing": [], "loaded": []})
    import main

    main.TIMEOUT_TASKS.clear()
    with TestClient(main.app) as c:
        iid = c.post("/api/ingest", json={"source": "gw", "log_type": "AUTH", "raw_text": BRUTE_FORCE_LOG}).json()["incident_id"]
        r = c.post(f"/api/incidents/{iid}/decision",
                   json={"decision": "APPROVED", "acknowledge_uncorroborated": True, "note": "checked with IdP"})
        assert r.status_code == 200 and r.json()["summary"]["threat_status"] == "CONTAINED"
        audit = [a for a in c.get(f"/api/incidents/{iid}/audit").json() if a["event"] == "hitl_decision"]
        assert audit[0]["acknowledged_uncorroborated"] is True
