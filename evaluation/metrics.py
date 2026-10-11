"""
evaluation/metrics.py — pure functions turning per-scenario results into the
benchmark table. Kept separate from the runner so every number is unit-tested.

Per-scenario result dict (built by scripts/eval.py):
  scenario_id, category, expected_attack_vector, acceptable_actions,
  acceptable_targets, expected_mitre, expected_playbook,
  incidents, predicted_attack_vector, predicted_mitre, best_playbook,
  planned_action, planned_target, proposal_ungrounded, executed_containment,
  tool_calls, latency_s, tokens, lines_total, lines_flagged, error

Metric definitions:
  triage_accuracy      attack + unknown scenarios: primary incident's vector == label
  triage_macro_f1      macro-F1 over the 7 vectors on the same scenarios
  attack_tag_jaccard   attack scenarios: mean Jaccard of ATT&CK *parent* technique
                       IDs (T1110.001 -> T1110), predicted vs labelled
  playbook_hit_rate    attack + unknown: forensics chose the labelled playbook
  action_correct       attack + unknown + fp_trap: the final plan's action is one the
                       playbook permits (no plan == NO_ACTION)
  target_correct       of correct non-NO_ACTION actions: target is acceptable
  invented_target_rate plans whose LLM-proposed target was NOT an extracted IOC
                       (caught and blocked by the grounding check)
  fp_containment_rate  fp_trap scenarios where a containment action was executed
  benign_filtered      benign scenarios that produced zero incidents (cheap filter)
  filter_reduction     share of all log lines removed by the cheap filter
  latency p50/p95      seconds per scenario that produced >= 1 incident
  tokens_per_incident  prompt + output tokens / incidents
"""

from __future__ import annotations

import statistics

VECTORS = ["BRUTE_FORCE_AUTH", "NETWORK_INTRUSION", "MALWARE_EXECUTION", "DATA_EXFILTRATION",
           "PRIVILEGE_ESCALATION", "PROXY_ANOMALY", "UNKNOWN"]


def _parent(tid: str) -> str:
    return tid.split(".")[0].upper()


def jaccard(a: list[str], b: list[str]) -> float:
    sa, sb = {_parent(x) for x in a}, {_parent(x) for x in b}
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def macro_f1(pairs: list[tuple[str, str]], labels: list[str] = VECTORS) -> float:
    f1s = []
    for label in labels:
        tp = sum(1 for y, p in pairs if y == label and p == label)
        fp = sum(1 for y, p in pairs if y != label and p == label)
        fn = sum(1 for y, p in pairs if y == label and p != label)
        if tp + fp + fn == 0:
            continue  # label absent from both truth and predictions
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1s.append(0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall))
    return sum(f1s) / len(f1s) if f1s else 0.0


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _rate(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def compute_metrics(results: list[dict]) -> dict:
    classified = [r for r in results if r["category"] in ("attack", "unknown") and r["incidents"] > 0]
    attacks = [r for r in results if r["category"] == "attack" and r["incidents"] > 0]
    judged = [r for r in results if r["category"] in ("attack", "unknown", "fp_trap") and r["incidents"] > 0]
    fps = [r for r in results if r["category"] == "fp_trap"]
    benign = [r for r in results if r["category"] == "benign"]
    with_incidents = [r for r in results if r["incidents"] > 0]

    pairs = [(r["expected_attack_vector"], r["predicted_attack_vector"] or "UNKNOWN") for r in classified]
    action_ok = [r for r in judged if (r["planned_action"] or "NO_ACTION") in r["acceptable_actions"]]
    targeted = [r for r in action_ok if (r["planned_action"] or "NO_ACTION") != "NO_ACTION"]
    target_ok = [r for r in targeted
                 if (r["planned_target"] or "").lower() in {t.lower() for t in r["acceptable_targets"]}]
    plans = [r for r in judged if r["planned_action"] is not None]
    total_lines = sum(r["lines_total"] for r in results)
    flagged = sum(r["lines_flagged"] for r in results)
    incidents = sum(r["incidents"] for r in results)

    def _split(rows: list[dict], difficulty: str) -> list[dict]:
        return [r for r in rows if r.get("difficulty", "standard") == difficulty]

    def _triage_acc(rows: list[dict]) -> float | None:
        return _rate(sum(1 for r in rows if r["predicted_attack_vector"] == r["expected_attack_vector"]), len(rows))

    def _action_acc(rows: list[dict]) -> float | None:
        return _rate(sum(1 for r in rows if (r["planned_action"] or "NO_ACTION") in r["acceptable_actions"]),
                     len(rows))

    per_vector = {}
    for v in VECTORS:
        rows = [r for r in classified if r["expected_attack_vector"] == v]
        if rows:
            per_vector[v] = sum(1 for r in rows if r["predicted_attack_vector"] == v) / len(rows)

    return {
        "scenarios": len(results),
        "errors": sum(1 for r in results if r.get("error")),
        "triage_accuracy": _rate(sum(1 for y, p in pairs if y == p), len(pairs)),
        "triage_macro_f1": macro_f1(pairs) if pairs else None,
        "triage_accuracy_standard": _triage_acc(_split(classified, "standard")),
        "triage_accuracy_hard": _triage_acc(_split(classified, "hard")),
        "action_correct_hard": _action_acc(_split(judged, "hard")),
        "attack_tag_jaccard": (statistics.mean(jaccard(r["predicted_mitre"], r["expected_mitre"]) for r in attacks)
                               if attacks else None),
        "playbook_hit_rate": _rate(sum(1 for r in classified if r["best_playbook"] == r["expected_playbook"]),
                                   len(classified)),
        "action_correct": _rate(len(action_ok), len(judged)),
        "target_correct": _rate(len(target_ok), len(targeted)),
        "invented_target_rate": _rate(sum(1 for r in plans if r["proposal_ungrounded"]), len(plans)),
        "fp_containment_rate": _rate(sum(1 for r in fps if r["executed_containment"]), len(fps)),
        "benign_filtered": _rate(sum(1 for r in benign if r["incidents"] == 0), len(benign)),
        "filter_reduction": _rate(total_lines - flagged, total_lines),
        "latency_p50_s": percentile([r["latency_s"] for r in with_incidents], 50),
        "latency_p95_s": percentile([r["latency_s"] for r in with_incidents], 95),
        "tokens_per_incident": (sum(r["tokens"] for r in results) / incidents) if incidents else 0.0,
        "tool_calls_per_incident": (sum(r["tool_calls"] for r in results) / incidents) if incidents else 0.0,
        "per_vector_accuracy": per_vector,
    }


ROWS = [
    ("Triage accuracy", "triage_accuracy", "pct"),
    ("  ↳ standard split (keyword-friendly)", "triage_accuracy_standard", "pct"),
    ("  ↳ hard split (vendor telemetry)", "triage_accuracy_hard", "pct"),
    ("Triage macro-F1", "triage_macro_f1", "f2"),
    ("ATT&CK tag Jaccard", "attack_tag_jaccard", "f2"),
    ("Playbook hit rate", "playbook_hit_rate", "pct"),
    ("Action correct (playbook-permitted)", "action_correct", "pct"),
    ("  ↳ hard split", "action_correct_hard", "pct"),
    ("Target correct", "target_correct", "pct"),
    ("Invented-target proposals (blocked)", "invented_target_rate", "pct"),
    ("False-positive traps contained (lower is better)", "fp_containment_rate", "pct"),
    ("Benign files filtered before any LLM call", "benign_filtered", "pct"),
    ("Log lines removed by cheap filter", "filter_reduction", "pct"),
    ("Latency p50 / scenario", "latency_p50_s", "s"),
    ("Latency p95 / scenario", "latency_p95_s", "s"),
    ("Tokens / incident", "tokens_per_incident", "int"),
    ("Forensics tool calls / incident", "tool_calls_per_incident", "f1"),
]


def _fmt(value, kind: str) -> str:
    if value is None:
        return "–"
    return {"pct": f"{value * 100:.1f}%", "f2": f"{value:.2f}", "f1": f"{value:.1f}",
            "s": f"{value:.1f}s", "int": f"{value:,.0f}"}[kind]


def render_markdown(metrics_by_model: dict[str, dict], scenario_count: int) -> str:
    models = list(metrics_by_model)
    lines = [f"| Metric ({scenario_count} scenarios) | " + " | ".join(f"`{m}`" for m in models) + " |",
             "|---|" + "---|" * len(models)]
    for label, key, kind in ROWS:
        lines.append(f"| {label} | " + " | ".join(_fmt(metrics_by_model[m].get(key), kind) for m in models) + " |")
    lines += ["", "| Per-vector triage accuracy | " + " | ".join(f"`{m}`" for m in models) + " |",
              "|---|" + "---|" * len(models)]
    for v in VECTORS:
        cells = [_fmt(metrics_by_model[m]["per_vector_accuracy"].get(v), "pct") for m in models]
        lines.append(f"| {v} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"
