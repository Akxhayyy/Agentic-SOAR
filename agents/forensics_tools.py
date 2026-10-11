"""
agents/forensics_tools.py

The forensics agent's toolbox. Every tool is READ-ONLY by construction:
  - search_playbooks         ChromaDB similarity query
  - get_related_logs         SELECT over the ingestion log store
  - lookup_prior_incidents   reads other incidents' checkpoints
  - check_local_threat_intel reads a bundled offline CSV blocklist

None of them import the execution layer, write files, or reach the
network. Each returns ToolResult(summary, data): `summary` is the short
text fed back to the LLM (and stored in forensics_trace); `data` is the
structured payload the forensics node aggregates (intel hits, related-log
counts, retrieved playbook chunks).

Arguments that name an indicator are restricted by the agent's JSON schema
to the incident's extracted IOC values, and re-checked here, so a tool can
never be pointed at an attacker-chosen string.
"""

from __future__ import annotations

import csv
import ipaddress
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from core.graph_config import load_config

logger = logging.getLogger("soar.forensics_tools")

MAX_SUMMARY_CHARS = 700


@dataclass
class ToolResult:
    summary: str
    data: dict = field(default_factory=dict)


@dataclass
class ToolContext:
    incident_id: str
    ioc_values: list[str]
    time_window: dict | None


def _clip(text: str) -> str:
    return text if len(text) <= MAX_SUMMARY_CHARS else text[: MAX_SUMMARY_CHARS - 3] + "..."


def _require_ioc(ctx: ToolContext, value: str) -> str:
    lowered = {v.lower(): v for v in ctx.ioc_values}
    if str(value).lower() not in lowered:
        raise ValueError(f"'{str(value)[:40]}' is not one of this incident's extracted IOCs")
    return lowered[str(value).lower()]


# --------------------------------------------------------------------------- tools

def search_playbooks(ctx: ToolContext, query: str) -> ToolResult:
    from rag.chroma_store import query_playbooks  # local import: tests patch the module attr

    matches = query_playbooks(query_text=str(query)[:500], top_k=4, similarity_floor=None)
    if not matches:
        return ToolResult("No playbook chunks matched.", {"matches": []})
    lines = [f"{m.playbook_id} ({m.similarity_score:.2f}): {m.chunk_text[:140].replace(chr(10), ' ')}"
             for m in matches]
    return ToolResult(_clip("\n".join(lines)), {"matches": [m.model_dump() for m in matches]})


def get_related_logs(ctx: ToolContext, indicator: str, window_s: int | None = None) -> ToolResult:
    from ingestion.log_store import related_lines

    value = _require_ioc(ctx, indicator)
    default_w = load_config()["forensics"]["agent"]["related_logs_default_window_s"]
    window = max(30, min(int(window_s or default_w), 3600))
    tw = ctx.time_window or {}
    rows = related_lines(value, tw.get("first_seen"), tw.get("last_seen"), window)
    if not rows:
        return ToolResult(f"No other log lines mention {value} within ±{window}s.", {"related_count": 0})
    suspicious = sum(r["suspicious"] for r in rows)
    reasons = sorted({r["reason"] for r in rows if r["reason"]})
    sample = [f"[{(r['ts'] or '?')[11:19]}] {r['raw_text'][:120]}" for r in rows[:5]]
    summary = (f"{len(rows)} line(s) mention {value} within ±{window}s "
               f"({suspicious} flagged suspicious; reasons: {', '.join(reasons) or 'none'}).\n"
               + "\n".join(sample))
    return ToolResult(_clip(summary), {"related_count": len(rows), "suspicious": suspicious, "reasons": reasons})


def lookup_prior_incidents(ctx: ToolContext, ioc: str) -> ToolResult:
    from core.checkpointer import thread_config_for_incident
    from core.graph import get_compiled_graph

    value = _require_ioc(ctx, ioc).lower()
    graph = get_compiled_graph()
    saver = graph.checkpointer
    try:
        with saver.cursor(transaction=False) as cur:
            cur.execute("SELECT DISTINCT thread_id FROM checkpoints LIMIT 500")
            thread_ids = [r[0] for r in cur.fetchall()]
    except Exception:  # noqa: BLE001 — empty DB / non-SQLite saver
        thread_ids = []

    hits = []
    for tid in thread_ids:
        if tid == ctx.incident_id:
            continue
        snap = graph.get_state(thread_config_for_incident(tid))
        values = snap.values if snap else {}
        iocs = ((values.get("triage") or {}).get("iocs")) or []
        if any(str(i.get("value", "")).lower() == value for i in iocs):
            hits.append({
                "incident_id": tid,
                "created_at": values.get("created_at"),
                "attack_vector": (values.get("triage") or {}).get("attack_vector"),
                "threat_status": values.get("threat_status"),
            })
    hits.sort(key=lambda h: h.get("created_at") or "", reverse=True)
    if not hits:
        return ToolResult(f"No prior incidents involve {ioc}.", {"prior": []})
    lines = [f"{h['incident_id'][:8]} {h['created_at'][:19] if h['created_at'] else '?'} "
             f"{h['attack_vector']} -> {h['threat_status']}" for h in hits[:5]]
    return ToolResult(_clip(f"{len(hits)} prior incident(s) involve {ioc}:\n" + "\n".join(lines)),
                      {"prior": [h["incident_id"] for h in hits[:20]]})


@lru_cache(maxsize=4)
def _load_blocklist(path: str, mtime: float) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(line for line in f if line.strip() and not line.lstrip().startswith("#"))
        for row in reader:
            rows.append({k: (v or "").strip() for k, v in row.items()})
    return rows


def blocklist() -> list[dict]:
    path = Path(load_config()["forensics"]["threat_intel_path"])
    if not path.exists():
        return []
    return _load_blocklist(str(path), path.stat().st_mtime)


def match_threat_intel(value: str) -> list[dict]:
    """Pure lookup (also used outside the agent): exact match, or IP-in-CIDR."""
    v = value.strip().lower()
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        ip = None
    hits = []
    for row in blocklist():
        ind = row["indicator"].lower()
        if row["type"] == "cidr" and ip is not None:
            try:
                if ip in ipaddress.ip_network(ind, strict=False):
                    hits.append(row)
            except ValueError:
                continue
        elif ind == v or (row["type"] == "process" and v.removesuffix(".exe") == ind.removesuffix(".exe")):
            hits.append(row)
    return hits


def check_local_threat_intel(ctx: ToolContext, ioc: str) -> ToolResult:
    value = _require_ioc(ctx, ioc)
    hits = match_threat_intel(value)
    if not hits:
        return ToolResult(f"{value}: no match in the local threat-intel feed.", {"intel_hits": []})
    desc = "; ".join(f"{h['severity'].upper()} {h['description']} ({h['source']})" for h in hits)
    return ToolResult(_clip(f"{value}: MATCH — {desc}"),
                      {"intel_hits": [{"ioc": value, **h} for h in hits]})


TOOLS = {
    "search_playbooks": search_playbooks,
    "get_related_logs": get_related_logs,
    "lookup_prior_incidents": lookup_prior_incidents,
    "check_local_threat_intel": check_local_threat_intel,
}

TOOL_DESCRIPTIONS = {
    "search_playbooks": "search_playbooks(query): semantic search over incident-response playbooks.",
    "get_related_logs": "get_related_logs(indicator, window_s): other ingested log lines mentioning an "
                        "IOC within +/- window_s seconds of this incident (30-3600, default 300).",
    "lookup_prior_incidents": "lookup_prior_incidents(ioc): earlier incidents that involved the same IOC.",
    "check_local_threat_intel": "check_local_threat_intel(ioc): match an IOC against the offline blocklist.",
}
