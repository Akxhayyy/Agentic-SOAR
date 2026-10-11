import { useMutation, useQuery } from "@tanstack/react-query";
import { Check, Cpu, Gauge, Loader2, ScrollText, ShieldCheck, X } from "lucide-react";
import { api } from "../lib/api";
import { absoluteTime } from "../lib/format";
import { ErrorNote, Kpi, Section, Spinner } from "../components/ui";

function Flag({ on, label, help }: { on: boolean; label: string; help: string }) {
  return (
    <li className="flex items-start gap-2.5">
      {on ? <Check aria-hidden className="mt-0.5 h-4 w-4 text-ok" /> : <X aria-hidden className="mt-0.5 h-4 w-4 text-crit" />}
      <div>
        <p className="text-sm text-fg">{label} <span className="text-xs text-faint">({on ? "on" : "OFF"})</span></p>
        <p className="text-xs text-muted">{help}</p>
      </div>
    </li>
  );
}

export default function SystemPage() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const config = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: Infinity });
  const audit = useQuery({ queryKey: ["audit"], queryFn: () => api.audit(50) });
  const bench = useMutation({ mutationFn: api.benchmark });
  const h = health.data;

  if (health.isLoading) return <Spinner label="Checking services" />;

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-fg">System</h1>
        <p className="text-sm text-muted">Local services, safety configuration and the audit trail.</p>
      </div>
      {health.isError && <ErrorNote error={health.error} />}

      {h && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Kpi label="Reasoning model" value={<span className="font-mono text-base">{h.reasoning_model}</span>}
               hint={h.ollama.missing.includes(h.reasoning_model) ? "not pulled" : `context ${h.num_ctx.toLocaleString()} tokens`} />
          <Kpi label="Playbook chunks" value={h.playbook_chunks} hint={h.embedding_model} />
          <Kpi label="GPU" icon={Cpu} value={<span className="text-base">{h.gpu?.name ?? "not detected"}</span>}
               hint={h.gpu ? `${(h.gpu.vram_used_mb / 1024).toFixed(1)} / ${(h.gpu.vram_total_mb / 1024).toFixed(1)} GB VRAM in use` : "CPU inference"} />
          <Kpi label="Execution mode" value={h.dry_run ? "Dry-run" : "LIVE"} hint={h.dry_run ? "actions are simulated" : "actions run real OS commands"} />
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <Section title={<span className="flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> Safety controls</span>}>
          {h && (
            <ul className="space-y-3">
              <Flag on={h.security.grounding} label="Evidence grounding" help="Plan targets must be extracted IOCs of a compatible type (enforced in the decoding grammar and after parsing)." />
              <Flag on={h.security.deny_list} label="Protected-asset deny-list" help="Loopback, this host and operator accounts are refused by the planner and, independently, the executor." />
              <Flag on={h.security.hash_check} label="Plan hash verification" help="The executor recomputes the plan's SHA-256 and aborts on any mismatch." />
              <Flag on={true} label="ASCII charset allow-list" help="Structural; not configurable. Blocks shell metacharacters and Unicode homoglyphs." />
              <Flag on={true} label={`Human approval (${h.hitl_timeout_seconds}s timeout → escalate)`} help="Nothing executes without an explicit APPROVE; silence escalates instead of executing." />
            </ul>
          )}
        </Section>

        <Section title={<span className="flex items-center gap-2"><Gauge className="h-4 w-4" /> Inference benchmark</span>}
                 action={<button className="btn-ghost px-2 py-1 text-xs" onClick={() => bench.mutate()} disabled={bench.isPending}>
                   {bench.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null} Run
                 </button>}>
          {bench.isError && <ErrorNote error={bench.error} />}
          {bench.data ? (
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <dt className="text-faint">Embedding latency</dt><dd className="font-mono text-fg">{bench.data.embedding_ms != null ? `${bench.data.embedding_ms} ms` : bench.data.embedding_error}</dd>
              <dt className="text-faint">Generation speed</dt><dd className="font-mono text-fg">{bench.data.tokens_per_s != null ? `${bench.data.tokens_per_s} tokens/s` : bench.data.reasoning_error}</dd>
              <dt className="text-faint">Output tokens</dt><dd className="font-mono text-fg">{bench.data.output_tokens ?? "—"}</dd>
              <dt className="text-faint">Model</dt><dd className="font-mono text-fg">{bench.data.model ?? "—"}</dd>
            </dl>
          ) : (
            <p className="text-sm text-muted">Measures real embedding latency and generation tokens/s from Ollama's own counters.</p>
          )}
        </Section>
      </div>

      <Section title={<span className="flex items-center gap-2"><ScrollText className="h-4 w-4" /> Audit log (latest 50)</span>}>
        {audit.data?.length ? (
          <div className="max-h-80 overflow-auto">
            <table className="w-full min-w-[36rem] text-xs">
              <tbody>
                {audit.data.map((a, i) => (
                  <tr key={i} className="border-b border-line/50">
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono text-faint">{absoluteTime(a.ts)}</td>
                    <td className="px-2 py-1.5 font-medium text-fg">{a.event}</td>
                    <td className="px-2 py-1.5 text-muted">{a.actor}</td>
                    <td className="px-2 py-1.5 font-mono text-muted">{a.incident_id?.slice(0, 8) ?? ""}</td>
                    <td className="px-2 py-1.5 text-muted">{["decision", "threat_status", "action", "filename"].map((k) => a[k] ? `${a[k]}` : "").filter(Boolean).join(" · ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="text-sm text-faint">No audit events yet.</p>}
      </Section>

      <Section title="Configuration (read-only)">
        {config.data ? (
          <pre className="max-h-96 overflow-auto rounded-md border border-line bg-bg p-3 font-mono text-xs text-muted">
            {JSON.stringify(config.data, null, 2)}
          </pre>
        ) : <Spinner />}
        <p className="mt-2 text-xs text-faint">Edit config/hitl_config.yaml and restart the backend to change these.</p>
      </Section>
    </div>
  );
}
