"""End-to-end graph + API tests with the fake LLM (no Ollama, no ChromaDB)."""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient
from langgraph.types import Command

from core.checkpointer import thread_config_for_incident
from core.uicr_schema import new_incident_state
from tests.conftest import BRUTE_FORCE_LOG


def _start(graph, text=BRUTE_FORCE_LOG):
    s = new_incident_state()
    s["raw_logs"] = [{"raw_text": text, "log_type": "AUTH", "source": "t"}]
    cfg = thread_config_for_incident(s["incident_id"])
    graph.invoke(s, cfg)
    return s["incident_id"], cfg


# --------------------------------------------------------------------------- graph

def test_pause_persists_phase_and_timestamp(graph):
    # Regression: hitl_gate_node's pre-interrupt writes were discarded, so the
    # checkpoint said NEUTRALIZER_PLANNED and had no pause time.
    _, cfg = _start(graph)
    snap = graph.get_state(cfg)
    assert snap.next == ("hitl_gate_node",)
    assert snap.values["current_phase"] == "AWAITING_HITL"
    assert snap.values["hitl_paused_at"]
    nodes = [h["node"] for h in snap.values["phase_history"]]
    assert nodes == ["triage", "forensics", "neutralizer", "hitl_arm"]


@pytest.mark.parametrize("decision,status,executed", [
    ("APPROVED", "CONTAINED", True),
    ("REJECTED", "OPEN", False),
    ("TIMEOUT", "ESCALATED", False),
])
def test_hitl_branches(graph, decision, status, executed):
    _, cfg = _start(graph)
    out = graph.invoke(Command(resume={"decision": decision, "note": "n"}), cfg)
    assert out["threat_status"] == status
    assert out["hitl_decision"] == decision
    assert bool(out.get("execution_result")) is executed
    assert out["current_phase"] == "REPORTED"
    assert out["hitl_operator_note"] == "n"


def test_forensics_miss_skips_neutralizer(graph, fake_rag, fake_llm):
    fake_rag.score = 0.3
    _, cfg = _start(graph)
    snap = graph.get_state(cfg)
    assert not snap.next
    assert snap.values["threat_status"] == "ESCALATED"
    assert snap.values["forensics"]["mode"] == "agent"
    assert snap.values["forensics"]["cleared_threshold"] is False
    assert fake_llm.count("planner") == 0
    assert snap.values["action_plan"] is None


def test_forensics_miss_two_pass_mode(graph, fake_rag, fake_llm, isolate_runtime):
    isolate_runtime["forensics"]["agent"]["enabled"] = False
    fake_rag.score = 0.3
    fake_llm.rerank = {"best_index": 0, "match_score": 0.4, "reason": "weak"}
    _, cfg = _start(graph)
    v = graph.get_state(cfg).values
    assert v["forensics"]["pass_count"] == 2 and v["forensics"]["mode"] == "two_pass"
    assert v["threat_status"] == "ESCALATED" and fake_llm.count("agent") == 0


def test_node_failure_is_recorded_not_raised(graph, fake_llm):
    # Regression: Ollama down => graph.invoke raised => HTTP 500, half-written incident.
    fake_llm.fail_on = "triage"
    _, cfg = _start(graph)
    v = graph.get_state(cfg).values
    assert v["current_phase"] == "FAILED" and "LLMUnavailableError" in v["error"]
    assert v["threat_status"] == "ESCALATED"
    assert v["report_path"]  # still audited
    assert fake_llm.count("planner") == 0


def test_resume_is_not_reentrant_after_completion(graph):
    _, cfg = _start(graph)
    graph.invoke(Command(resume={"decision": "APPROVED"}), cfg)
    assert not graph.get_state(cfg).next


# --------------------------------------------------------------------------- API

@pytest.fixture
def client(graph, monkeypatch):
    monkeypatch.setattr("agents.llm_client.ollama_status",
                        lambda models: {"online": True, "pulled": models, "missing": [], "loaded": []})
    monkeypatch.setattr("rag.chroma_store.collection_count", lambda: 31)
    import main

    main.TIMEOUT_TASKS.clear()
    main.JOBS.clear()
    with TestClient(main.app) as c:
        yield c


def _ingest(client):
    r = client.post("/api/ingest", json={"source": "gw", "log_type": "AUTH", "raw_text": BRUTE_FORCE_LOG})
    assert r.status_code == 200
    return r.json()["incident_id"]


def test_api_ingest_list_and_detail(client):
    iid = _ingest(client)
    listing = client.get("/api/incidents").json()
    assert listing[0]["incident_id"] == iid and listing[0]["awaiting_hitl"]
    assert listing[0]["mitre_techniques"] == ["T1110", "T1078"]
    detail = client.get(f"/api/incidents/{iid}").json()
    assert detail["summary"]["hitl_timeout_remaining_seconds"] > 0
    assert detail["dry_run"] is True


def test_api_unknown_incident_is_404(client):
    # Regression: unknown IDs returned 200 with an empty state.
    assert client.get("/api/incidents/does-not-exist").status_code == 404
    assert client.get("/incident/does-not-exist").status_code == 404


def test_api_double_approve_is_409(client):
    iid = _ingest(client)
    r1 = client.post(f"/api/incidents/{iid}/decision", json={"decision": "APPROVED", "note": "ok"})
    r2 = client.post(f"/api/incidents/{iid}/decision", json={"decision": "APPROVED"})
    assert r1.status_code == 200 and r1.json()["summary"]["threat_status"] == "CONTAINED"
    assert r2.status_code == 409


def test_api_concurrent_decisions_resume_once(client, fake_llm):
    iid = _ingest(client)
    codes = []

    def decide(d):
        codes.append(client.post(f"/api/incidents/{iid}/decision", json={"decision": d}).status_code)

    threads = [threading.Thread(target=decide, args=(d,)) for d in ("APPROVED", "REJECTED", "APPROVED")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(codes) == [200, 409, 409]
    assert fake_llm.count("report") == 1


def test_api_rejects_system_only_decision(client):
    iid = _ingest(client)
    assert client.post(f"/api/incidents/{iid}/decision", json={"decision": "TIMEOUT"}).status_code == 400


def test_api_timeout_fires(client, isolate_runtime):
    isolate_runtime["hitl"]["timeout_seconds"] = 1
    iid = _ingest(client)
    deadline = time.time() + 10
    while time.time() < deadline:
        s = client.get(f"/api/incidents/{iid}").json()["summary"]
        if s["threat_status"] == "ESCALATED":
            break
        time.sleep(0.2)
    assert s["hitl_decision"] == "TIMEOUT" and s["threat_status"] == "ESCALATED"


def test_timeout_rearmed_after_restart(graph, isolate_runtime, monkeypatch):
    # Regression: watchers lived only in memory; after a restart paused incidents never timed out.
    iid, cfg = _start(graph)          # paused, no API process watching it
    isolate_runtime["hitl"]["timeout_seconds"] = 1
    time.sleep(1.1)                   # deadline already passed "while the backend was down"
    monkeypatch.setattr("agents.llm_client.ollama_status",
                        lambda models: {"online": True, "pulled": models, "missing": [], "loaded": []})
    import main

    main.TIMEOUT_TASKS.clear()
    with TestClient(main.app) as c:
        # Poll for the FINAL status: hitl_decision is checkpointed by the gate node
        # before the report node sets threat_status, so it appears first.
        deadline = time.time() + 10
        while time.time() < deadline:
            s = c.get(f"/api/incidents/{iid}").json()["summary"]
            if s["threat_status"] == "ESCALATED":
                break
            time.sleep(0.2)
        assert s["threat_status"] == "ESCALATED" and s["hitl_decision"] == "TIMEOUT"


def test_api_rollback_once(client):
    iid = _ingest(client)
    client.post(f"/api/incidents/{iid}/decision", json={"decision": "APPROVED"})
    r1 = client.post(f"/api/incidents/{iid}/rollback", json={"operator": "alice"})
    assert r1.status_code == 200 and r1.json()["action"] == "unlock_account"
    assert client.post(f"/api/incidents/{iid}/rollback", json={}).status_code == 409
    assert client.get(f"/api/incidents/{iid}").json()["summary"]["rolled_back"]
    events = [e["event"] for e in client.get(f"/api/incidents/{iid}/audit").json()]
    assert {"ingest", "hitl_decision", "rollback"} <= set(events)


def test_api_rollback_requires_execution(client):
    iid = _ingest(client)
    assert client.post(f"/api/incidents/{iid}/rollback", json={}).status_code == 409


def test_api_batch_job_runs_in_background(client):
    text = "\n".join(f"2026-06-23T22:00:0{i}Z failed login for user admin from 10.0.4.17" for i in range(5))
    r = client.post("/api/ingest_file", json={"file_text": text, "filename": "t.log"})
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    deadline = time.time() + 10
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("done", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "done" and job["total_groups"] == 1 and job["completed"] == 1
    assert job["incidents"][0]["phase_reached"] == "AWAITING_HITL"


def test_api_preview_and_samples(client):
    r = client.post("/api/ingest_file/preview", json={"file_text": "x\nfailed login for user a from 1.2.3.4"})
    assert r.json()["suspicious_lines"] == 1
    names = [s["name"] for s in client.get("/api/samples").json()]
    assert "demo_attack.txt" in names
    assert client.get("/api/samples/..%2Fmain.py").status_code == 404


def test_api_health_and_report(client):
    h = client.get("/api/health").json()
    assert h["backend"] and h["ollama"]["online"] and h["playbook_chunks"] == 31
    iid = _ingest(client)
    assert client.get(f"/api/incidents/{iid}/report").status_code == 404
    client.post(f"/api/incidents/{iid}/decision", json={"decision": "APPROVED"})
    md = client.get(f"/api/incidents/{iid}/report").json()["markdown"]
    assert "LOCK_ACCOUNT" in md and "CONTAINED" in md


def test_legacy_routes_still_work(client):
    r = client.post("/ingest", json={"source": "gw", "log_type": "AUTH", "raw_text": BRUTE_FORCE_LOG})
    iid = r.json()["incident_id"]
    assert client.get(f"/incident/{iid}").json()["paused_at"] == ["hitl_gate_node"]
    assert client.post(f"/resume/{iid}", json={"decision": "REJECTED"}).status_code == 200
