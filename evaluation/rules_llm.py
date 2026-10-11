"""
evaluation/rules_llm.py

A deterministic, keyword-rule stand-in for the LLM ("rules baseline").

Two uses:
  1. CI smoke runs of scripts/eval.py / scripts/redteam.py with no Ollama.
  2. A reference column in the benchmark table: what does a plain
     keyword classifier + "playbook first-choice action" policy score on
     the same scenarios, through the same guarded pipeline? The gap between
     this row and the LLM rows is what the models actually add.

rules_baseline() patches the LLM call and the playbook retrieval for the
duration of a `with` block and restores them afterwards.
"""

from __future__ import annotations

import json
import re
from contextlib import contextmanager

VECTOR_RULES: list[tuple[str, re.Pattern]] = [
    ("MALWARE_EXECUTION", re.compile(r"ransomware|malware|trojan|reverse shell|powershell -enc|base64 -d|"
                                     r"wget |xmrig|mimikatz", re.I)),
    ("DATA_EXFILTRATION", re.compile(r"\bscp\b|\brsync\b|exfil|bulk (transfer|export|upload)|paste-drop", re.I)),
    ("PRIVILEGE_ESCALATION", re.compile(r"\bsudo\b|chmod|uid=0|privilege escalation|setuid|kernel exploit", re.I)),
    ("PROXY_ANOMALY", re.compile(r"CONNECT \d|socks|proxy bypass|X-Forwarded-For|tunnel", re.I)),
    ("NETWORK_INTRUSION", re.compile(r"nmap|masscan|port scan|dport=", re.I)),
    ("BRUTE_FORCE_AUTH", re.compile(r"failed login|authentication failure|invalid password", re.I)),
]

PLAYBOOK = {
    "BRUTE_FORCE_AUTH": "brute_force_auth.md",
    "NETWORK_INTRUSION": "network_intrusion.md",
    "MALWARE_EXECUTION": "malware_execution.md",
    "DATA_EXFILTRATION": "data_exfiltration.md",
    "PRIVILEGE_ESCALATION": "privilege_escalation.md",
    "PROXY_ANOMALY": "proxy_anomaly.md",
    "UNKNOWN": "unknown_threat.md",
}

MITRE = {
    "BRUTE_FORCE_AUTH": ["T1110"],
    "NETWORK_INTRUSION": ["T1046"],
    "MALWARE_EXECUTION": ["T1059"],
    "DATA_EXFILTRATION": ["T1048"],
    "PRIVILEGE_ESCALATION": ["T1548"],
    "PROXY_ANOMALY": ["T1090"],
    "UNKNOWN": [],
}

PREFERRED_ACTIONS = {
    "BRUTE_FORCE_AUTH": ["LOCK_ACCOUNT", "ISOLATE_HOST"],
    "NETWORK_INTRUSION": ["ISOLATE_HOST"],
    "MALWARE_EXECUTION": ["TERMINATE_PROCESS", "ISOLATE_HOST"],
    "DATA_EXFILTRATION": ["LOCK_ACCOUNT", "BLOCK_PROXY_IP"],
    "PRIVILEGE_ESCALATION": ["LOCK_ACCOUNT"],
    "PROXY_ANOMALY": ["BLOCK_PROXY_IP", "LOCK_ACCOUNT"],
    "UNKNOWN": [],
}

_VECTOR_FROM_TEXT = re.compile(r"(?:Attack vector(?: \(from triage\))?|Attack type):\s*([A-Za-z_ ]+?)[.\n]")


def classify(text: str) -> str:
    for vector, pattern in VECTOR_RULES:
        if pattern.search(text):
            return vector
    return "UNKNOWN"


def _vector_in_prompt(prompt: str) -> str:
    m = _VECTOR_FROM_TEXT.search(prompt + "\n")
    if not m:
        return "UNKNOWN"
    return m.group(1).strip().upper().replace(" ", "_")


def _branches(schema: dict | None) -> list[dict]:
    if not schema:
        return []
    return schema.get("anyOf") or [schema]


class RulesLLM:
    """Callable with the same signature as agents.llm_client.call_reasoning_model_ex."""

    def __call__(self, system_prompt, user_prompt, model, num_ctx, temperature,
                 schema=None, timeout_s=180.0, max_tokens=None):
        from agents.llm_client import LLMResponse

        if "triage analyst" in system_prompt:
            logs = user_prompt
            vector = classify(logs)
            body = {
                "attack_vector": vector,
                "discovered_layout": "rules baseline",
                "iocs": [],  # the deterministic regex extractor fills these in
                "triage_summary": logs.replace("<logs>", "").strip().splitlines()[0][:400] if logs.strip() else "",
                "triage_confidence": 0.6,
                "mitre_techniques": MITRE[vector],
            }
        elif "forensics investigator" in system_prompt:
            vector = _vector_in_prompt(user_prompt)
            actions = {b["properties"]["action"]["const"]: b for b in _branches(schema)}
            if "check_local_threat_intel" in actions and "(no tool calls yet)" in user_prompt:
                ioc = actions["check_local_threat_intel"]["properties"]["args"]["properties"]["ioc"]["enum"][0]
                body = {"thought": "rules: check intel", "action": "check_local_threat_intel", "args": {"ioc": ioc}}
            elif "final" not in actions:
                body = {"thought": "rules: search", "action": "search_playbooks", "args": {"query": vector}}
            else:
                body = {"thought": "rules: map vector to playbook", "action": "final",
                        "args": {"best_playbook": PLAYBOOK.get(vector, "unknown_threat.md"),
                                 "confidence": 0.6, "rationale": "keyword rules baseline"}}
        elif "containment planner" in system_prompt:
            vector = _vector_in_prompt(user_prompt)
            available = {b["properties"]["action_type"]["const"]: b["properties"]["target"]["enum"]
                         for b in _branches(schema) if "const" in b["properties"].get("action_type", {})}
            body = {"action_type": "NO_ACTION", "target": "none", "params": {},
                    "justification": "rules baseline: no preferred action available"}
            for action in PREFERRED_ACTIONS.get(vector, []):
                if available.get(action):
                    body = {"action_type": action, "target": available[action][0], "params": {},
                            "justification": f"rules baseline: playbook first-choice {action}"}
                    break
        elif "judge how well" in system_prompt:
            body = {"best_index": 0, "match_score": 0.75, "reason": "rules baseline"}
        else:
            return LLMResponse(text="### Executive Summary\nRules baseline run.", model="rules",
                               prompt_tokens=0, output_tokens=0, duration_s=0.0)
        return LLMResponse(text=json.dumps(body), model="rules", prompt_tokens=0, output_tokens=0, duration_s=0.0)


def rules_query_playbooks(query_text: str, top_k: int, similarity_floor: float | None):
    from core.uicr_schema import PlaybookMatch

    vector = _vector_in_prompt(query_text) if "Attack type" in query_text else classify(query_text)
    if vector not in PLAYBOOK:
        vector = classify(query_text)
    book = PLAYBOOK[vector]
    out = [PlaybookMatch(playbook_id=book, chunk_text=f"# {book}\n## Containment Steps\n(rules baseline)",
                         similarity_score=0.80)]
    if book != "unknown_threat.md":
        out.append(PlaybookMatch(playbook_id="unknown_threat.md", chunk_text="# unknown\n## Detection Criteria",
                                 similarity_score=0.50))
    return out[:top_k]


@contextmanager
def rules_baseline():
    import agents.forensics as forensics
    import agents.llm_client as llm
    import rag.chroma_store as chroma

    saved = (llm.call_reasoning_model_ex, forensics.query_playbooks, chroma.query_playbooks)
    llm.call_reasoning_model_ex = RulesLLM()
    forensics.query_playbooks = rules_query_playbooks
    chroma.query_playbooks = rules_query_playbooks
    try:
        yield
    finally:
        llm.call_reasoning_model_ex, forensics.query_playbooks, chroma.query_playbooks = saved
