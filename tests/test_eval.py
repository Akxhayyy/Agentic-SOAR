"""Tests for scripts/eval.py (benchmark harness)."""

from __future__ import annotations

import importlib.util
import json
import sys

import pytest

from core.graph_config import PROJECT_ROOT


def _load_eval():
    spec = importlib.util.spec_from_file_location("soar_eval", PROJECT_ROOT / "scripts" / "eval.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["soar_eval"] = mod  # dataclasses resolve their module via sys.modules
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def ev():
    return _load_eval()


def _write(tmp_path, rows):
    p = tmp_path / "s.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return p


SCENARIO = {"id": "bf-1", "category": "attack", "logs": ["failed login for user a from 1.2.3.4"],
            "expected_attack_vector": "BRUTE_FORCE_AUTH", "expected_action_type": "LOCK_ACCOUNT",
            "expected_target": "a", "mitre": ["T1110"]}


def test_load_scenarios_and_limit(ev, tmp_path):
    path = _write(tmp_path, [SCENARIO, {**SCENARIO, "id": "bf-2"}])
    assert [s.id for s in ev.load_scenarios(path)] == ["bf-1", "bf-2"]
    assert len(ev.load_scenarios(path, limit=1)) == 1


def test_load_scenarios_rejects_bad_rows(ev, tmp_path):
    path = _write(tmp_path, [{"id": "x"}])
    with pytest.raises(ValueError, match="invalid scenario"):
        ev.load_scenarios(path)


def test_unpulled_models_are_skipped(ev, monkeypatch):
    monkeypatch.setattr("agents.llm_client.ollama_status",
                        lambda req: {"online": True, "missing": ["gemma4:e4b"], "pulled": [], "loaded": []})
    ok, missing = ev.available_models(["qwen3:8b", "gemma4:e4b"])
    assert ok == ["qwen3:8b"] and missing == ["gemma4:e4b"]


def test_offline_ollama_skips_everything(ev, monkeypatch):
    monkeypatch.setattr("agents.llm_client.ollama_status",
                        lambda req: {"online": False, "missing": req, "pulled": [], "loaded": []})
    assert ev.available_models(["qwen3:8b"]) == ([], ["qwen3:8b"])


def test_rules_baseline_never_needs_ollama(ev, monkeypatch):
    monkeypatch.setattr("agents.llm_client.ollama_status",
                        lambda req: {"online": False, "missing": req, "pulled": [], "loaded": []})
    assert ev.available_models(["rules", "qwen3:8b"]) == (["rules"], ["qwen3:8b"])


# --------------------------------------------------------------------------- dataset

def test_shipped_benchmark_is_valid_and_balanced(ev):
    from collections import Counter

    from ingestion.batch_processor import preview_log_file

    rows = ev.load_scenarios(PROJECT_ROOT / "data" / "benchmark" / "scenarios.jsonl")
    assert len(rows) == 150
    cats = Counter(r.expected_attack_vector if r.category == "attack" else r.category for r in rows)
    assert all(cats[v] >= 12 for v in ("BRUTE_FORCE_AUTH", "NETWORK_INTRUSION", "MALWARE_EXECUTION",
                                       "DATA_EXFILTRATION", "PRIVILEGE_ESCALATION", "PROXY_ANOMALY"))
    assert cats["benign"] >= 10 and cats["fp_trap"] >= 10 and cats["unknown"] >= 5
    assert sum(r.difficulty == "hard" for r in rows) >= 20
    for r in rows:
        text = "\n".join(r.logs)
        groups = preview_log_file(text)["groups"]
        assert (len(groups) == 0) == (r.category == "benign"), r.id
        for t in r.acceptable_targets:
            assert t == "none" or t.lower() in text.lower(), (r.id, t)


def test_generator_is_deterministic():
    spec = importlib.util.spec_from_file_location("gen_bench", PROJECT_ROOT / "scripts" / "gen_benchmark.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert gen.build(7) == gen.build(7)
    assert gen.build(7) != gen.build(8)


# --------------------------------------------------------------------------- metrics

def _row(**kw):
    base = {"scenario_id": "x", "category": "attack", "difficulty": "standard",
            "expected_attack_vector": "BRUTE_FORCE_AUTH", "acceptable_actions": ["LOCK_ACCOUNT"],
            "acceptable_targets": ["bob"], "expected_mitre": ["T1110.001"], "expected_playbook": "brute_force_auth.md",
            "incidents": 1, "predicted_attack_vector": "BRUTE_FORCE_AUTH", "predicted_mitre": ["T1110"],
            "best_playbook": "brute_force_auth.md", "planned_action": "LOCK_ACCOUNT", "planned_target": "bob",
            "proposal_ungrounded": False, "executed_containment": True, "tool_calls": 2, "latency_s": 10.0,
            "tokens": 1000, "lines_total": 10, "lines_flagged": 8, "error": None}
    base.update(kw)
    return base


def test_metric_definitions():
    from evaluation.metrics import compute_metrics, jaccard, macro_f1, percentile

    assert jaccard(["T1110.001"], ["T1110"]) == 1.0          # parent-technique match
    assert jaccard(["T1110", "T1078"], ["T1110"]) == 0.5
    assert macro_f1([("A", "A"), ("B", "A")], ["A", "B"]) == pytest.approx((2 / 3 + 0) / 2)
    assert percentile([1, 2, 3, 4], 50) == 2.5

    rows = [
        _row(),
        _row(predicted_attack_vector="UNKNOWN", planned_action=None, planned_target=None,
             executed_containment=False, difficulty="hard"),
        _row(category="fp_trap", acceptable_actions=["NO_ACTION"], acceptable_targets=["none"],
             planned_action="LOCK_ACCOUNT", executed_containment=True),
        _row(category="fp_trap", acceptable_actions=["NO_ACTION"], acceptable_targets=["none"],
             planned_action="NO_ACTION", planned_target="none", executed_containment=False),
        _row(category="benign", incidents=0, lines_flagged=0, acceptable_actions=["NONE"]),
        _row(planned_target="alice", proposal_ungrounded=True),
    ]
    m = compute_metrics(rows)
    assert m["triage_accuracy"] == pytest.approx(2 / 3)
    assert m["triage_accuracy_hard"] == 0.0 and m["triage_accuracy_standard"] == 1.0
    assert m["fp_containment_rate"] == 0.5
    assert m["benign_filtered"] == 1.0
    assert m["target_correct"] == pytest.approx(1 / 2)       # bob ok, alice wrong
    assert m["invented_target_rate"] == pytest.approx(1 / 4)
    assert m["filter_reduction"] == pytest.approx(1 - 40 / 60)


def test_eval_end_to_end_with_rules_baseline(ev, tmp_path, monkeypatch):
    rc = ev.main(["--fake-llm", "--stratified", "1", "--out", str(tmp_path)])
    assert rc == 0
    run = next(tmp_path.glob("run_*"))
    data = json.loads((run / "results.json").read_text(encoding="utf-8"))
    rules = data["metrics"]["rules"]
    assert rules["scenarios"] == len(data["results"]["rules"]) >= 10
    assert rules["benign_filtered"] == 1.0 and rules["errors"] == 0
    assert "| Triage accuracy |" in (run / "results.md").read_text(encoding="utf-8")


def test_isolated_runtime_forces_dry_run_and_restores(tmp_path, isolate_runtime):
    from evaluation.runner import isolated_runtime

    isolate_runtime["execution"]["dry_run"] = False
    before = json.dumps(isolate_runtime, sort_keys=True, default=str)
    with isolated_runtime(tmp_path, model="m", security={"grounding": False}):
        assert isolate_runtime["execution"]["dry_run"] is True
        assert isolate_runtime["security"]["grounding"] is False
    assert json.dumps(isolate_runtime, sort_keys=True, default=str) == before
