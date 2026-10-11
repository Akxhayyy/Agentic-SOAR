import { useQuery } from "@tanstack/react-query";
import { FlaskConical, ShieldAlert } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { vectorLabel } from "../lib/format";
import { EmptyState, ErrorNote, Section, Spinner } from "../components/ui";

// Mirrors evaluation/metrics.py ROWS so the UI and README tables agree.
const ROWS: [string, string, "pct" | "f2" | "s" | "int" | "f1"][] = [
  ["Triage accuracy", "triage_accuracy", "pct"],
  ["  standard split", "triage_accuracy_standard", "pct"],
  ["  hard split (vendor telemetry)", "triage_accuracy_hard", "pct"],
  ["Triage macro-F1", "triage_macro_f1", "f2"],
  ["ATT&CK tag Jaccard", "attack_tag_jaccard", "f2"],
  ["Playbook hit rate", "playbook_hit_rate", "pct"],
  ["Action correct", "action_correct", "pct"],
  ["  hard split", "action_correct_hard", "pct"],
  ["Target correct", "target_correct", "pct"],
  ["Invented-target proposals (blocked)", "invented_target_rate", "pct"],
  ["False-positive traps contained ↓", "fp_containment_rate", "pct"],
  ["Benign files filtered", "benign_filtered", "pct"],
  ["Lines removed by cheap filter", "filter_reduction", "pct"],
  ["Latency p50", "latency_p50_s", "s"],
  ["Latency p95", "latency_p95_s", "s"],
  ["Tokens / incident", "tokens_per_incident", "int"],
  ["Tool calls / incident", "tool_calls_per_incident", "f1"],
];

function fmt(v: unknown, kind: string): string {
  if (v == null || typeof v !== "number") return "—";
  switch (kind) {
    case "pct": return `${(v * 100).toFixed(1)}%`;
    case "f2": return v.toFixed(2);
    case "f1": return v.toFixed(1);
    case "s": return `${v.toFixed(1)}s`;
    default: return Math.round(v).toLocaleString();
  }
}

const notFound = (e: unknown) => e instanceof ApiError && e.status === 404;

export default function EvaluationPage() {
  const ev = useQuery({ queryKey: ["eval"], queryFn: api.evalLatest, retry: false });
  const rt = useQuery({ queryKey: ["redteam"], queryFn: api.redteamLatest, retry: false });

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-fg">Evaluation</h1>
        <p className="text-sm text-muted">Latest offline benchmark and prompt-injection red-team results (dry-run, isolated runtime).</p>
      </div>

      <Section title={<span className="flex items-center gap-2"><FlaskConical className="h-4 w-4" /> Benchmark</span>}
               action={ev.data && <span className="text-xs text-faint">{ev.data.scenarios} scenarios · {ev.data.stamp}</span>}>
        {ev.isLoading ? <Spinner /> : notFound(ev.error) ? (
          <EmptyState icon={FlaskConical} title="No benchmark run yet">
            Run <code className="font-mono">python scripts/eval.py --models rules,qwen3:8b</code> (or <code className="font-mono">--fake-llm</code> for the rules baseline only).
          </EmptyState>
        ) : ev.isError ? <ErrorNote error={ev.error} /> : ev.data && (() => {
          const models = Object.keys(ev.data.metrics);
          const perVector = Object.fromEntries(models.map((m) => [m, (ev.data!.metrics[m].per_vector_accuracy ?? {}) as Record<string, number>]));
          const vectors = [...new Set(models.flatMap((m) => Object.keys(perVector[m])))];
          return (
            <div className="space-y-5">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[32rem] text-sm">
                  <thead>
                    <tr className="border-b border-line text-left">
                      <th className="label px-3 py-2">Metric</th>
                      {models.map((m) => <th key={m} className="px-3 py-2 text-right font-mono text-xs font-medium text-fg">{m}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {ROWS.map(([label, key, kind]) => (
                      <tr key={key} className="border-b border-line/50">
                        <td className={`px-3 py-1.5 ${label.startsWith("  ") ? "pl-7 text-muted" : "text-fg"}`}>{label.trim()}</td>
                        {models.map((m) => (
                          <td key={m} className="px-3 py-1.5 text-right font-mono tabular-nums text-fg">{fmt(ev.data!.metrics[m][key], kind)}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[32rem] text-sm">
                  <thead>
                    <tr className="border-b border-line text-left">
                      <th className="label px-3 py-2">Triage accuracy by vector</th>
                      {models.map((m) => <th key={m} className="px-3 py-2 text-right font-mono text-xs font-medium text-fg">{m}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {vectors.map((v) => (
                      <tr key={v} className="border-b border-line/50">
                        <td className="px-3 py-1.5 text-fg">{vectorLabel(v)}</td>
                        {models.map((m) => <td key={m} className="px-3 py-1.5 text-right font-mono tabular-nums">{fmt(perVector[m][v], "pct")}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {ev.data.skipped?.length > 0 && (
                <p className="text-xs text-faint">Skipped (not pulled in Ollama): {ev.data.skipped.join(", ")}</p>
              )}
            </div>
          );
        })()}
      </Section>

      <Section title={<span className="flex items-center gap-2"><ShieldAlert className="h-4 w-4" /> Red team: attack success rate</span>}
               action={rt.data && <span className="text-xs text-faint">{rt.data.stamp}</span>}>
        {rt.isLoading ? <Spinner /> : notFound(rt.error) ? (
          <EmptyState icon={ShieldAlert} title="No red-team run yet">
            Run <code className="font-mono">python scripts/redteam.py</code> (no Ollama needed: it uses a deliberately hijacked model).
          </EmptyState>
        ) : rt.isError ? <ErrorNote error={rt.error} /> : rt.data && Object.entries(rt.data.summary).map(([model, s]) => (
          <div key={model} className="space-y-2">
            <p className="text-xs text-muted">
              Model: <span className="font-mono text-fg">{model === "hijacked" ? "hijacked (worst case: obeys every injection)" : model}</span>, operator auto-approves everything.
              Lower is better.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[36rem] text-sm">
                <thead>
                  <tr className="border-b border-line text-left">
                    <th className="label px-3 py-2">Attack class</th>
                    <th className="label px-3 py-2 text-right">Payloads</th>
                    <th className="label px-3 py-2 text-right">Defences off</th>
                    <th className="label px-3 py-2 text-right">Defences on</th>
                    <th className="label px-3 py-2">Stopped by</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(s.by_class).map(([cls, c]) => (
                    <tr key={cls} className="border-b border-line/50">
                      <td className="px-3 py-1.5 text-fg">{cls.replace(/_/g, " ")}</td>
                      <td className="px-3 py-1.5 text-right font-mono tabular-nums">{c.payloads}</td>
                      <td className="px-3 py-1.5 text-right font-mono tabular-nums">{fmt(c.asr_off, "pct")}</td>
                      <td className="px-3 py-1.5 text-right font-mono tabular-nums font-semibold">{fmt(c.asr_on, "pct")}</td>
                      <td className="px-3 py-1.5 text-xs text-muted">
                        {Object.entries(c.blocked_by_on).map(([k, n]) => `${k} ×${n}`).join(", ") || (cls === "evidence_poisoning" ? "residual risk: HITL" : "—")}
                      </td>
                    </tr>
                  ))}
                  <tr>
                    <td className="px-3 py-2 font-semibold text-fg">All payloads</td>
                    <td />
                    <td className="px-3 py-2 text-right font-mono font-semibold tabular-nums">{fmt(s.overall.off, "pct")}</td>
                    <td className="px-3 py-2 text-right font-mono font-semibold tabular-nums">{fmt(s.overall.on, "pct")}</td>
                    <td className="px-3 py-2 text-xs text-muted">excluding evidence poisoning: {fmt(s.overall.off_excl_poisoning, "pct")} → {fmt(s.overall.on_excl_poisoning, "pct")}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </Section>
    </div>
  );
}
