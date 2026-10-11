"""
scripts/redteam.py — runs the prompt-injection / tampering suite with
defences OFF and ON and reports the attack success rate per attack class.

  python scripts/redteam.py                         # worst case: hijacked LLM (no Ollama needed)
  python scripts/redteam.py --models hijacked,qwen3:8b

"hijacked" is a deliberately compromised model that does whatever the
injected log text asks (evaluation/redteam.py). Real model tags run the
actual LLM against the same payloads (needs Ollama; unpulled tags are
skipped). Every run is dry-run and isolated (evaluation/runner.py).
Output: data/redteam/run_<ts>/results.{md,json}
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_PAYLOADS = ROOT / "tests" / "redteam" / "payloads.jsonl"
DEFAULT_OUT = ROOT / "data" / "redteam"


def run_suite(payloads: list[dict], model: str, run_dir: Path) -> list[dict]:
    from evaluation.redteam import DEFENCES_OFF, DEFENCES_ON, run_payload

    rows = []
    for p in payloads:
        for mode, defences in (("off", DEFENCES_OFF), ("on", DEFENCES_ON)):
            row = run_payload(p, defences, run_dir / model.replace(":", "_").replace("/", "_") / f"{p['id']}_{mode}",
                              model=None if model == "hijacked" else model)
            rows.append(row)
            print(f"  [{model}] {p['id']} {p['attack_class']:<20} defences {mode:<3} -> "
                  f"{'ATTACK SUCCEEDED' if row['success'] else 'blocked: ' + str(row['blocked_by'])}", flush=True)
    return rows


def main(argv: list[str] | None = None) -> int:
    from evaluation.redteam import load_payloads, render_markdown, summarize

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--payloads", type=Path, default=DEFAULT_PAYLOADS)
    p.add_argument("--models", default="hijacked")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    payloads = load_payloads(args.payloads)
    requested = [m.strip() for m in args.models.split(",") if m.strip()]
    real = [m for m in requested if m != "hijacked"]
    if real:
        from agents.llm_client import ollama_status

        status = ollama_status(real)
        missing = set(real) if not status["online"] else set(status["missing"])
        for m in missing:
            print(f"[skip] {m}: not pulled in Ollama")
        requested = [m for m in requested if m not in missing]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.out / f"run_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    report, all_rows = [f"# Red-team results ({stamp})\n", f"{len(payloads)} payloads · HITL auto-approve\n"], {}
    for model in requested:
        rows = run_suite(payloads, model, run_dir)
        all_rows[model] = rows
        label = "hijacked LLM (worst case)" if model == "hijacked" else model
        report.append(render_markdown(summarize(rows), label))
    (run_dir / "results.md").write_text("\n".join(report), encoding="utf-8")
    (run_dir / "results.json").write_text(json.dumps(
        {"stamp": stamp, "rows": all_rows, "summary": {m: summarize(r) for m, r in all_rows.items()}}, indent=1),
        encoding="utf-8")
    print("\n" + "\n".join(report))
    print(f"Wrote {run_dir / 'results.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
