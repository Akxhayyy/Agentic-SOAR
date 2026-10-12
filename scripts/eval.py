"""
scripts/eval.py — benchmark harness.

Runs every labelled scenario in data/benchmark/scenarios.jsonl through the
REAL pipeline (cheap filter -> grouping -> triage -> forensics agent ->
neutralizer -> HITL -> wrapper -> report), with the HITL gate auto-decided,
in an isolated runtime (own DB / reports / log store, dry_run forced on).
Writes per-model metrics as Markdown + JSON:

  triage accuracy / macro-F1 · ATT&CK tag accuracy · playbook hit rate ·
  action + target correctness · invented-target rate · false-positive
  containment · p50/p95 latency · tokens per incident · cheap-filter reduction

Usage:
  python scripts/eval.py                                   # all default models
  python scripts/eval.py --models rules,qwen3:8b --limit 30
  python scripts/eval.py --fake-llm                        # rules baseline only, no Ollama

"rules" is a deterministic keyword baseline (evaluation/rules_llm.py), run
through the same guarded pipeline as the LLMs. Models that aren't pulled in
Ollama are skipped. Results stream to data/eval/run_<ts>/<model>.jsonl so
a long run can be inspected (or salvaged) while it is still going.

Dataset row: {"id", "category", "logs": [...], "expected_attack_vector",
  "expected_action_type", "expected_target", "acceptable_actions",
  "acceptable_targets", "mitre", "expected_playbook", "notes"}
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_DATASET = ROOT / "data" / "benchmark" / "scenarios.jsonl"
DEFAULT_OUT = ROOT / "data" / "eval"
FOUNDATION_SEC = "hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"
DEFAULT_MODELS = ["rules", "qwen3:8b", "gemma4:e4b", FOUNDATION_SEC, "qwen2.5:3b-instruct"]
RULES = "rules"


@dataclass
class Scenario:
    id: str
    category: str
    logs: list[str]
    expected_attack_vector: str
    expected_action_type: str
    expected_target: str | None = None
    acceptable_actions: list[str] = field(default_factory=list)
    acceptable_targets: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    expected_playbook: str = ""
    notes: str = ""
    difficulty: str = "standard"           # standard | hard | public
    acceptable_vectors: list[str] = field(default_factory=list)  # multi-label real data
    source: str = "synthetic"


def load_scenarios(path: Path, limit: int | None = None) -> list[Scenario]:
    scenarios = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                scenarios.append(Scenario(**json.loads(line)))
            except (json.JSONDecodeError, TypeError) as e:
                raise ValueError(f"{path}:{n}: invalid scenario ({e})") from e
    return scenarios[:limit] if limit else scenarios


def available_models(requested: list[str]) -> tuple[list[str], list[str]]:
    """Splits requested models into (runnable, missing). "rules" never needs Ollama."""
    from agents.llm_client import ollama_status

    llm_models = [m for m in requested if m != RULES]
    status = ollama_status(llm_models) if llm_models else {"online": True, "missing": []}
    missing = set(llm_models) if not status["online"] else set(status["missing"])
    return [m for m in requested if m not in missing], [m for m in requested if m in missing]


def scenario_result(sc: Scenario, out) -> dict:
    from evaluation.runner import containment_executed, primary_state

    prim = primary_state(out.states) or {}
    triage = prim.get("triage") or {}
    forensics = prim.get("forensics") or {}
    plan = prim.get("action_plan")
    return {
        "scenario_id": sc.id,
        "category": sc.category,
        "difficulty": sc.difficulty,
        "expected_attack_vector": sc.expected_attack_vector,
        "acceptable_vectors": sc.acceptable_vectors or [sc.expected_attack_vector],
        "acceptable_actions": sc.acceptable_actions or [sc.expected_action_type],
        "acceptable_targets": sc.acceptable_targets,
        "expected_mitre": sc.mitre,
        "expected_playbook": sc.expected_playbook,
        "incidents": len(out.states),
        "predicted_attack_vector": triage.get("attack_vector"),
        "predicted_mitre": triage.get("mitre_techniques", []),
        "best_playbook": forensics.get("best_playbook"),
        "forensics_score": forensics.get("final_similarity_score"),
        "planned_action": plan.get("action_type") if plan else None,
        "planned_target": plan.get("target") if plan else None,
        "proposal_ungrounded": any((s.get("action_plan") or {}).get("grounded") is False for s in out.states),
        "executed_containment": any(containment_executed(s) for s in out.states),
        "threat_status": prim.get("threat_status"),
        "tool_calls": sum(len([t for t in (s.get("forensics_trace") or []) if t.get("tool") != "final"])
                          for s in out.states),
        "latency_s": out.elapsed_s,
        "tokens": out.usage.get("prompt_tokens", 0) + out.usage.get("output_tokens", 0),
        "lines_total": out.total_lines,
        "lines_flagged": out.flagged_lines,
        "error": next((s.get("error") for s in out.states if s.get("error")), None),
    }


def run_model(model: str, scenarios: list[Scenario], run_dir: Path, decision: str) -> list[dict]:
    from contextlib import nullcontext

    from evaluation.rules_llm import rules_baseline
    from evaluation.runner import isolated_runtime, run_logs

    safe_name = model.replace("/", "_").replace(":", "_")
    stream = run_dir / f"{safe_name}.jsonl"
    results = []
    baseline = rules_baseline() if model == RULES else nullcontext()
    with baseline, isolated_runtime(run_dir / safe_name, model=None if model == RULES else model) as graph:
        for i, sc in enumerate(scenarios, 1):
            try:
                out = run_logs(graph, "\n".join(sc.logs), decision=decision)
                row = scenario_result(sc, out)
            except Exception as e:  # noqa: BLE001 — one broken scenario must not end a 3-hour run
                row = {**scenario_result(sc, _empty_output()), "error": f"{type(e).__name__}: {e}"[:300]}
            results.append(row)
            with open(stream, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            if sc.category == "benign":
                ok = "ok " if row["incidents"] == 0 else "MISS"
            else:
                ok = "ok " if (row["planned_action"] or "NO_ACTION") in row["acceptable_actions"] else "MISS"
            print(f"  [{model}] {i:>3}/{len(scenarios)} {sc.id:<8} {ok} "
                  f"{row['predicted_attack_vector'] or '-':<22} {row['planned_action'] or '-':<18} "
                  f"{row['latency_s']:>6.1f}s", flush=True)
    return results


def _empty_output():
    from evaluation.runner import RunOutput

    return RunOutput(states=[], total_lines=0, flagged_lines=0, elapsed_s=0.0, usage={})


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dataset", type=Path, action="append",
                   help="scenario JSONL file; repeat to combine (default: the synthetic benchmark). "
                        "Public data: --dataset data/benchmark/otrf_scenarios.jsonl")
    p.add_argument("--models", default=",".join(DEFAULT_MODELS),
                   help='comma-separated Ollama tags; "rules" = keyword baseline; unpulled models are skipped')
    p.add_argument("--limit", type=int, default=None, help="only run the first N scenarios")
    p.add_argument("--stratified", type=int, default=None,
                   help="run N scenarios per category/vector instead of the first N overall")
    p.add_argument("--decision", default="APPROVED", choices=["APPROVED", "REJECTED"],
                   help="auto-decision applied at the HITL gate")
    p.add_argument("--fake-llm", action="store_true", help="run only the rules baseline (no Ollama)")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return p.parse_args(argv)


def stratify(scenarios: list[Scenario], per_group: int) -> list[Scenario]:
    picked, counts = [], {}
    for sc in scenarios:
        key = (sc.expected_attack_vector if sc.category == "attack" else sc.category) + sc.difficulty
        if counts.get(key, 0) < per_group:
            counts[key] = counts.get(key, 0) + 1
            picked.append(sc)
    return picked


def main(argv: list[str] | None = None) -> int:
    from evaluation.metrics import compute_metrics, render_markdown

    args = parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows cp1252 consoles
    datasets = args.dataset or [DEFAULT_DATASET]
    scenarios = [sc for path in datasets for sc in load_scenarios(path)]
    if args.stratified:
        scenarios = stratify(scenarios, args.stratified)
    if args.limit:
        scenarios = scenarios[: args.limit]

    requested = [RULES] if args.fake_llm else [m.strip() for m in args.models.split(",") if m.strip()]
    models, skipped = available_models(requested)
    for m in skipped:
        print(f"[skip] {m}: not pulled in Ollama (ollama pull {m})")
    if not models:
        print("No runnable models.")
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.out / f"run_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"{len(scenarios)} scenarios x {len(models)} model(s): {', '.join(models)} -> {run_dir}")

    metrics_by_model, results_by_model = {}, {}
    for model in models:
        results = run_model(model, scenarios, run_dir, args.decision)
        results_by_model[model] = results
        metrics_by_model[model] = compute_metrics(results)

    table = render_markdown(metrics_by_model, len(scenarios))
    header = (f"# Benchmark results ({stamp})\n\nDatasets: {', '.join(f'`{d.name}`' for d in datasets)} · "
              f"scenarios: {len(scenarios)} · "
              f"HITL auto-decision: {args.decision} · skipped (not pulled): {', '.join(skipped) or 'none'}\n\n")
    (run_dir / "results.md").write_text(header + table, encoding="utf-8")
    (run_dir / "results.json").write_text(json.dumps(
        {"stamp": stamp, "datasets": [str(d) for d in datasets], "scenarios": len(scenarios), "skipped": skipped,
         "metrics": metrics_by_model, "results": results_by_model}, indent=1), encoding="utf-8")
    print("\n" + table)
    print(f"Wrote {run_dir / 'results.md'} and results.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
