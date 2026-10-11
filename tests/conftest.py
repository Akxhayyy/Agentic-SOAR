"""
Shared pytest fixtures. No Ollama, no ChromaDB, no real infra:

- isolate_runtime (autouse): points every runtime path (reports, exec
  results, audit log, checkpointer DB) at tmp_path and forces safe security
  defaults, by mutating the single cached config dict in place (every module
  shares that object through load_config()).
- fake_llm: replaces agents.llm_client.call_reasoning_model_ex with a
  scripted FakeLLM that routes on the system prompt (triage / rerank /
  planner / report). Tests tweak fake_llm.triage etc. per scenario.
- fake_rag: replaces the ChromaDB lookup used by the forensics agent.
- graph: a freshly compiled graph on a temp SqliteSaver, installed as the
  process-wide compiled graph so main.py and batch_processor use it too.
"""

from __future__ import annotations

import copy
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.graph_config import load_config  # noqa: E402
from core.uicr_schema import PlaybookMatch  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_runtime(tmp_path):
    cfg = load_config()
    saved = copy.deepcopy(cfg)
    cfg["execution"].update(
        dry_run=True,
        exec_result_dir=str(tmp_path / "exec_results"),
        report_dir=str(tmp_path / "reports"),
    )
    cfg["hitl"]["checkpointer_db_path"] = str(tmp_path / "graph_state.db")
    cfg["logging"]["audit_log_path"] = str(tmp_path / "audit.log")
    cfg["forensics"]["log_store_path"] = str(tmp_path / "logstore.db")
    cfg["forensics"]["agent"].update(enabled=True, max_tool_calls=5)
    cfg["security"].update(grounding=True, deny_list=True, hash_check=True)
    yield cfg
    cfg.clear()
    cfg.update(saved)


class FakeLLM:
    """Scripted stand-in for Ollama. Each attribute is the JSON/text to return."""

    def __init__(self):
        self.triage = {
            "attack_vector": "BRUTE_FORCE_AUTH",
            "discovered_layout": "unstructured text",
            "iocs": [
                {"ioc_type": "IP_ADDRESS", "value": "10.0.4.17", "confidence": 0.95},
                {"ioc_type": "USERNAME", "value": "admin", "confidence": 0.9},
            ],
            "triage_summary": "Repeated failed logins for admin from 10.0.4.17 followed by a success.",
            "triage_confidence": 0.9,
            "mitre_techniques": ["T1110", "T1078"],
        }
        self.rerank = {"best_index": 0, "match_score": 0.8, "reason": "Covers the burst pattern."}
        self.plan = {
            "action_type": "LOCK_ACCOUNT",
            "target": "admin",
            "params": {},
            "justification": "Burst of failures then success; playbook step 1 says lock the account.",
        }
        self.report = "### Executive Summary\nBrute force contained.\n"
        # Forensics agent: scripted steps, consumed in order; when exhausted the
        # agent is given self.agent_final.
        self.agent_steps: list[dict] = [
            {"thought": "Check the source IP.", "action": "check_local_threat_intel", "args": {"ioc": "10.0.4.17"}},
        ]
        self.agent_final = {"thought": "Clear brute-force pattern.", "action": "final",
                            "args": {"best_playbook": "brute_force_auth.md", "confidence": 0.9,
                                     "rationale": "Failure burst then success from one IP."}}
        self.fail_on: str | None = None  # "triage" | "planner" | "report" -> raise
        self.calls: list[dict] = []

    def _route(self, system_prompt: str) -> str:
        if "triage analyst" in system_prompt:
            return "triage"
        if "judge how well" in system_prompt:
            return "rerank"
        if "containment planner" in system_prompt:
            return "planner"
        if "narrative section" in system_prompt:
            return "report"
        if "forensics investigator" in system_prompt:
            return "agent"
        return "other"

    def __call__(self, system_prompt, user_prompt, model, num_ctx, temperature,
                 schema=None, timeout_s=180.0, max_tokens=None):
        from agents.llm_client import LLMResponse, LLMUnavailableError

        kind = self._route(system_prompt)
        self.calls.append({"kind": kind, "user_prompt": user_prompt, "schema": schema, "model": model})
        if self.fail_on == kind:
            raise LLMUnavailableError("fake: Ollama is not reachable")
        if kind == "agent":
            allowed = {b["properties"]["action"]["const"] for b in schema.get("anyOf", [schema])}
            step = self.agent_steps.pop(0) if self.agent_steps and len(allowed) > 1 else self.agent_final
            return LLMResponse(text=json.dumps(step), model=model, prompt_tokens=100, output_tokens=40,
                               duration_s=0.01)
        body = {"triage": self.triage, "rerank": self.rerank, "planner": self.plan}.get(kind)
        text = body if isinstance(body, str) else (json.dumps(body) if body is not None else self.report)
        return LLMResponse(text=text, model=model, prompt_tokens=100, output_tokens=50, duration_s=0.01)

    def count(self, kind: str) -> int:
        return sum(1 for c in self.calls if c["kind"] == kind)


@pytest.fixture
def fake_llm(monkeypatch):
    fake = FakeLLM()
    monkeypatch.setattr("agents.llm_client.call_reasoning_model_ex", fake)
    return fake


class FakeRAG:
    def __init__(self):
        self.score = 0.82
        self.playbook = "brute_force_auth.md"

    def __call__(self, query_text, top_k, similarity_floor):
        if self.score <= 0:
            return []
        return [
            PlaybookMatch(
                playbook_id=self.playbook,
                chunk_text="## Containment Steps\n1. If the account shows a successful login after a burst "
                           "of failures, recommend LOCK_ACCOUNT.",
                similarity_score=self.score,
            ),
            PlaybookMatch(playbook_id="unknown_threat.md", chunk_text="## Detection Criteria\n...",
                          similarity_score=max(0.0, self.score - 0.2)),
        ][:top_k]


@pytest.fixture
def fake_rag(monkeypatch):
    rag = FakeRAG()
    monkeypatch.setattr("agents.forensics.query_playbooks", rag)
    monkeypatch.setattr("rag.chroma_store.query_playbooks", rag)  # used by the search_playbooks tool
    return rag


@pytest.fixture
def graph(isolate_runtime, fake_llm, fake_rag, monkeypatch):
    from langgraph.checkpoint.sqlite import SqliteSaver

    import core.graph as core_graph

    conn = sqlite3.connect(isolate_runtime["hitl"]["checkpointer_db_path"], check_same_thread=False)
    compiled = core_graph.build_graph(checkpointer=SqliteSaver(conn))
    monkeypatch.setattr(core_graph, "compiled_graph", compiled)
    yield compiled
    conn.close()


BRUTE_FORCE_LOG = (
    "Failed login for user admin from 10.0.4.17 x14 in 45s, "
    "followed by successful login for user admin from 10.0.4.17"
)
