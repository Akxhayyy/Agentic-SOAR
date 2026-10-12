"""
agents/corroboration.py

Independent-evidence check for destructive containment plans — the
system's answer to EVIDENCE POISONING (THREAT_MODEL.md §7).

Grounding proves a plan's target appears in the incident's logs. That is
necessary but not sufficient: an attacker who can write log lines can make
an innocent account "appear in the evidence". Corroboration asks a second
question — does anything OTHER than this incident's own lines point at the
same target? It counts deterministic signals (no LLM involved, so it can't
be argued into "corroborated"):

  incident_evidence      the target appears in the incident's own lines (baseline)
  second_telemetry_type  incident lines about the target come from >= 2 telemetry
                         types (e.g. AUTH and EDR) — two pipelines, not one
  independent_source     suspicious activity for the target in a DIFFERENT
                         ingested batch/feed within the window
  threat_intel           the target matches the offline threat-intel feed
  prior_incident         the target was involved in an earlier incident

A destructive plan is "corroborated" when count >= security.corroboration
.min_signals (default 2: the incident evidence plus one independent signal).

Policy (deliberately NOT a hard block — most real alerts are single-source):
an uncorroborated destructive plan can only be executed if the operator
explicitly acknowledges it ("I verified this independently"). The API
requires the acknowledgement, and the execution wrapper RE-RUNS this
assessment itself rather than trusting the stored result.

Residual risk: an attacker who can forge lines in two independent feeds
defeats this too (measured in the red team).
"""

from __future__ import annotations

import logging

from core.graph_config import load_config

logger = logging.getLogger("soar.corroboration")


def _settings() -> dict:
    c = load_config()["security"].get("corroboration") or {}
    return {
        "enabled": c.get("enabled", True),
        "min_signals": int(c.get("min_signals", 2)),
        "window_s": int(c.get("window_s", 3600)),
    }


def assess(state: dict, action_type: str, target: str) -> dict:
    """Pure function of (state, log store, threat-intel feed, checkpoints)."""
    cfg = _settings()
    applies = cfg["enabled"] and action_type not in (None, "NO_ACTION") and target not in (None, "", "none")
    result = {"applies": applies, "signals": [], "count": 0, "required": cfg["min_signals"], "met": True}
    if not applies:
        return result

    t = target.lower()
    signals: list[dict] = []

    own = [e for e in (state.get("raw_logs") or []) if t in str(e.get("raw_text", "")).lower()]
    if own:
        signals.append({"kind": "incident_evidence", "detail": f"{len(own)} incident line(s) mention {target}"})
        types = {str(e.get("log_type", "")).upper() for e in own if e.get("log_type")}
        if len(types) >= 2:
            signals.append({"kind": "second_telemetry_type", "detail": "telemetry types: " + ", ".join(sorted(types))})

    try:
        from ingestion.log_store import related_lines

        tw = state.get("time_window") or {}
        rows = related_lines(target, tw.get("first_seen"), tw.get("last_seen"), cfg["window_s"])
        other = [r for r in rows if r.get("suspicious") and r.get("batch_id") != state.get("source_batch")]
        if other:
            signals.append({"kind": "independent_source",
                            "detail": f"{len(other)} suspicious line(s) in {len({r['batch_id'] for r in other})} other feed(s)"})
    except Exception:  # noqa: BLE001 — a missing store is "no signal", never a crash
        logger.debug("log store unavailable for corroboration", exc_info=True)

    from agents.forensics_tools import match_threat_intel

    hits = match_threat_intel(target)
    if hits:
        signals.append({"kind": "threat_intel", "detail": "; ".join(h["description"] for h in hits)[:200]})

    try:
        from agents.forensics_tools import ToolContext, lookup_prior_incidents

        prior = lookup_prior_incidents(
            ToolContext(incident_id=state.get("incident_id", ""), ioc_values=[target], time_window=None), target,
        ).data.get("prior", [])
        if prior:
            signals.append({"kind": "prior_incident", "detail": f"{len(prior)} earlier incident(s) involve {target}"})
    except Exception:  # noqa: BLE001
        logger.debug("prior-incident lookup unavailable for corroboration", exc_info=True)

    result.update(signals=signals, count=len(signals), met=len(signals) >= cfg["min_signals"])
    return result
