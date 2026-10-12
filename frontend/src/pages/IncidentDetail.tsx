import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft, BookOpen, Check, CheckCircle2, Download, FileText, Fingerprint, Gavel, Loader2,
  Microscope, Radar, RotateCcw, Search, ShieldAlert, ShieldCheck, Undo2, Wrench, X, XCircle, Zap,
  type LucideIcon,
} from "lucide-react";
import { api, type IncidentDetail, type TraceStep } from "../lib/api";
import { useNow } from "../lib/events";
import { absoluteTime, actionLabel, duration, hitlRemaining, pct, shortId, vectorLabel } from "../lib/format";
import {
  CountdownRing, ErrorNote, LogViewer, Markdown, MitreChips, ScoreBar, Section, Spinner, StatusBadge, statusKey,
} from "../components/ui";

type StepState = "done" | "active" | "pending" | "skipped" | "failed";

function Step({ icon: Icon, title, state, meta, children, last = false }:
  { icon: LucideIcon; title: string; state: StepState; meta?: ReactNode; children?: ReactNode; last?: boolean }) {
  const ring = {
    done: "border-accent text-accent", active: "border-hitl text-hitl", pending: "border-line text-faint",
    skipped: "border-line text-faint", failed: "border-crit text-crit",
  }[state];
  return (
    <li className="relative flex gap-4 pb-6">
      {!last && <span aria-hidden className="absolute left-[15px] top-9 h-[calc(100%-2.25rem)] w-px bg-line" />}
      <span className={`relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 bg-surface ${ring}`}>
        {state === "active" ? <Loader2 aria-hidden className="h-4 w-4 animate-spin" /> : <Icon aria-hidden className="h-4 w-4" />}
      </span>
      <div className="min-w-0 flex-1 pt-1">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h3 className={`text-sm font-semibold ${state === "pending" || state === "skipped" ? "text-faint" : "text-fg"}`}>
            {title}
            {state === "skipped" && <span className="ml-2 text-xs font-normal">skipped</span>}
          </h3>
          {meta && <span className="text-xs text-faint">{meta}</span>}
        </div>
        {children && <div className="mt-2 space-y-3">{children}</div>}
      </div>
    </li>
  );
}

const TOOL_ICON: Record<string, LucideIcon> = {
  search_playbooks: Search,
  get_related_logs: Radar,
  lookup_prior_incidents: Fingerprint,
  check_local_threat_intel: ShieldAlert,
  final: CheckCircle2,
};

function Trace({ steps }: { steps: TraceStep[] }) {
  if (!steps.length) return null;
  return (
    <div>
      <p className="label mb-1.5">Investigation ({steps.filter((s) => s.tool !== "final").length} tool calls)</p>
      <ol className="space-y-1.5">
        {steps.map((s) => {
          const Icon = TOOL_ICON[s.tool] ?? Wrench;
          const args = Object.entries(s.args ?? {})
            .filter(([k]) => s.tool !== "final" || k === "best_playbook")
            .map(([k, v]) => `${k}=${String(v)}`).join(", ");
          return (
            <li key={s.step} className="rounded-md border border-line bg-bg px-3 py-2">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                <Icon aria-hidden className="h-3.5 w-3.5 text-accent" />
                <span className="font-mono text-fg">{s.tool}</span>
                {args && <span className="truncate font-mono text-muted">({args})</span>}
                <span className="ml-auto tabular-nums text-faint">{duration(s.duration_ms / 1000)}</span>
              </div>
              {s.result_summary && (
                <p className={`mt-1 whitespace-pre-line text-xs ${s.result_summary.startsWith("tool error") ? "text-crit" : "text-muted"}`}>
                  {s.result_summary}
                </p>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

const SIGNAL_LABELS: Record<string, string> = {
  incident_evidence: "Incident evidence",
  second_telemetry_type: "Second telemetry type",
  independent_source: "Independent feed",
  threat_intel: "Threat-intel match",
  prior_incident: "Prior incident",
};

/** Independent signals behind a destructive plan (agents/corroboration.py). */
function CorroborationBox({ corr }: { corr: NonNullable<IncidentDetail["state"]["corroboration"]> }) {
  return (
    <div className="rounded-md border border-line bg-bg p-3">
      <p className="label flex items-center gap-1.5">
        {corr.met ? <Check aria-hidden className="h-3.5 w-3.5 text-ok" /> : <ShieldAlert aria-hidden className="h-3.5 w-3.5 text-med" />}
        Corroboration: {corr.count} of {corr.required} independent signals {corr.met ? "(met)" : "(not met)"}
      </p>
      <ul className="mt-1.5 space-y-0.5 text-xs">
        {corr.signals.map((s) => (
          <li key={s.kind}><span className="text-fg">{SIGNAL_LABELS[s.kind] ?? s.kind}</span> <span className="text-muted">· {s.detail}</span></li>
        ))}
      </ul>
    </div>
  );
}

function KV({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap gap-x-3 text-sm">
      <span className="w-28 shrink-0 text-faint">{k}</span>
      <span className="min-w-0 text-fg">{children}</span>
    </div>
  );
}

function useOperatorName(): [string, (v: string) => void] {
  const [name, setName] = useState(() => {
    try { return localStorage.getItem("soar-operator") ?? "operator"; } catch { return "operator"; }
  });
  useEffect(() => {
    try { localStorage.setItem("soar-operator", name); } catch { /* storage unavailable */ }
  }, [name]);
  return [name, setName];
}

function DecisionPanel({ d, now }: { d: IncidentDetail; now: number }) {
  const qc = useQueryClient();
  const plan = d.state.action_plan!;
  const [note, setNote] = useState("");
  const [operator, setOperator] = useOperatorName();
  const [confirmText, setConfirmText] = useState("");
  const [ackUncorroborated, setAck] = useState(false);
  const remaining = hitlRemaining(d.state.hitl_paused_at, d.hitl_timeout_seconds, now) ?? d.hitl_timeout_seconds;
  const needsTypedConfirm = !d.dry_run && plan.action_type !== "NO_ACTION";
  const corr = d.state.corroboration;
  const needsAck = !!corr?.applies && !corr.met;
  const decide = useMutation({
    mutationFn: (decision: "APPROVED" | "REJECTED") =>
      api.decide(d.incident_id, decision, note, operator, decision === "APPROVED" && ackUncorroborated),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["incident", d.incident_id] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  return (
    <section className="card border-hitl/50" aria-labelledby="decision-title">
      <header className="flex items-center gap-4 border-b border-line px-4 py-3">
        <CountdownRing remaining={remaining} total={d.hitl_timeout_seconds} />
        <div>
          <h2 id="decision-title" className="text-sm font-semibold text-fg">Your decision is needed</h2>
          <p className="text-xs text-muted">Escalates automatically when the timer runs out. Nothing runs without approval.</p>
        </div>
      </header>
      <div className="space-y-3 p-4">
        <div className="rounded-md border border-line bg-bg p-3">
          <p className="label">Proposed action</p>
          <p className="mt-1 text-base font-semibold text-fg">
            {actionLabel(plan.action_type)}{" "}
            {plan.target !== "none" && <span className="font-mono text-accent">{plan.target}</span>}
          </p>
          <p className="mt-1.5 text-sm text-muted">{plan.justification}</p>
          <p className="mt-2 flex items-center gap-1.5 text-xs">
            {plan.grounded
              ? <><Check aria-hidden className="h-3.5 w-3.5 text-ok" /><span className="text-muted">{plan.grounding_note || "Target grounded in evidence"}</span></>
              : <><X aria-hidden className="h-3.5 w-3.5 text-crit" /><span className="text-fg">Blocked: {plan.grounding_note}</span></>}
          </p>
          <p className="mt-1 text-xs text-faint">{d.dry_run ? "Dry-run: the action will be simulated." : "LIVE: this runs a real OS command."}</p>
        </div>

        {corr?.applies && <CorroborationBox corr={corr} />}
        {needsAck && (
          <label className="flex items-start gap-2 rounded-md border border-med/50 bg-med/10 p-2.5 text-xs text-fg">
            <input type="checkbox" className="mt-0.5" checked={ackUncorroborated} onChange={(e) => setAck(e.target.checked)} />
            <span>
              Only {corr!.count} of {corr!.required} independent signals. I verified this target through another
              source (call, EDR console, IdP logs) and accept that the evidence could be forged.
            </span>
          </label>
        )}

        <label className="block">
          <span className="label">Note for the audit log (optional)</span>
          <textarea className="input mt-1 h-16 resize-y" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)}
                    placeholder="Why you approved or rejected…" />
        </label>
        <label className="block">
          <span className="label">Operator</span>
          <input className="input mt-1" maxLength={64} value={operator} onChange={(e) => setOperator(e.target.value)} />
        </label>
        {needsTypedConfirm && (
          <label className="block">
            <span className="label">Type <span className="font-mono normal-case text-fg">{plan.target}</span> to enable approval</span>
            <input className="input mt-1 font-mono" value={confirmText} onChange={(e) => setConfirmText(e.target.value)} />
          </label>
        )}
        {decide.isError && <ErrorNote error={decide.error} />}
        <div className="grid grid-cols-2 gap-2">
          <button className="btn-ghost" disabled={decide.isPending} onClick={() => decide.mutate("REJECTED")}>
            <X className="h-4 w-4" /> Reject
          </button>
          <button className="btn-primary" onClick={() => decide.mutate("APPROVED")}
                  disabled={decide.isPending || (needsTypedConfirm && confirmText !== plan.target) || (needsAck && !ackUncorroborated)}>
            {decide.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Approve
          </button>
        </div>
      </div>
    </section>
  );
}

function OutcomePanel({ d }: { d: IncidentDetail }) {
  const qc = useQueryClient();
  const s = d.state;
  const [confirming, setConfirming] = useState(false);
  const [operator] = useOperatorName();
  const rollback = useMutation({
    mutationFn: () => api.rollback(d.incident_id, operator, ""),
    onSettled: () => qc.invalidateQueries({ queryKey: ["incident", d.incident_id] }),
  });
  const canRollback = s.execution_result?.success && s.execution_result.action_type !== "NO_ACTION" && !s.rollback_result;

  return (
    <Section title="Outcome">
      <div className="space-y-3">
        <StatusBadge status={statusKey(d.summary)} size="md" />
        <KV k="Decision">{s.hitl_decision}{s.hitl_operator_note && <span className="text-muted"> — “{s.hitl_operator_note}”</span>}</KV>
        {s.execution_result && (
          <KV k="Executed">
            {actionLabel(s.execution_result.action_type)}{" "}
            <span className="font-mono">{s.execution_result.target}</span>{" "}
            <span className="text-faint">({s.execution_result.dry_run ? "dry-run" : "live"})</span>
          </KV>
        )}
        {s.rollback_result && (
          <KV k="Rolled back">by {s.rollback_result.by} · {absoluteTime(s.rollback_result.at)}</KV>
        )}
        {s.error && <ErrorNote error={s.error} />}
        {rollback.isError && <ErrorNote error={rollback.error} />}
        {canRollback && (confirming ? (
          <div className="flex gap-2">
            <button className="btn-danger flex-1" onClick={() => rollback.mutate()} disabled={rollback.isPending}>
              <Undo2 className="h-4 w-4" /> Confirm rollback
            </button>
            <button className="btn-ghost" onClick={() => setConfirming(false)}>Cancel</button>
          </div>
        ) : (
          <button className="btn-ghost w-full" onClick={() => setConfirming(true)}>
            <RotateCcw className="h-4 w-4" /> Roll back containment
          </button>
        ))}
      </div>
    </Section>
  );
}

function BackLink() {
  return (
    <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-fg">
      <ArrowLeft className="h-4 w-4" /> All incidents
    </Link>
  );
}

export default function IncidentDetailPage() {
  const { id = "" } = useParams();
  const now = useNow(1000);
  const q = useQuery({ queryKey: ["incident", id], queryFn: () => api.incident(id), refetchInterval: 20000 });
  const config = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: Infinity });
  const d = q.data;
  const reportQ = useQuery({ queryKey: ["incident", id, "report", d?.state.report_path], queryFn: () => api.report(id),
                             enabled: !!d?.state.report_path });
  const auditQ = useQuery({ queryKey: ["incident", id, "audit", d?.state.current_phase], queryFn: () => api.incidentAudit(id) });
  const mitreNames: Record<string, string> = config.data?.mitre?.allowed_techniques ?? {};

  const timing = useMemo(() => {
    const t: Record<string, number> = {};
    for (const h of d?.state.phase_history ?? []) t[h.node] = (t[h.node] ?? 0) + h.duration_s;
    return t;
  }, [d]);

  if (q.isLoading) return <Spinner label="Loading incident" />;
  if (q.isError || !d) return <div className="mx-auto max-w-3xl space-y-3"><BackLink /><ErrorNote error={q.error ?? "Not found"} /></div>;

  const s = d.state;
  const ran = (node: string) => node in timing;
  const failedAt = s.error?.split(":")[0];
  const stepState = (node: string, skipped = false): StepState =>
    failedAt === node ? "failed" : ran(node) ? "done" : skipped ? "skipped" : s.current_phase === "FAILED" ? "skipped" : "active";
  const awaiting = d.summary.awaiting_hitl;
  const forensicsMissed = !!s.forensics && !s.forensics.cleared_threshold;
  const lines = s.raw_logs.map((l) => l.raw_text);
  const downloadReport = () => {
    const blob = new Blob([reportQ.data?.markdown ?? ""], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `incident_${id}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <BackLink />
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-semibold text-fg">{s.triage ? vectorLabel(s.triage.attack_vector) : "New incident"}</h1>
            <StatusBadge status={statusKey(d.summary)} size="md" />
          </div>
          <p className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
            <span className="font-mono" title={id}>#{shortId(id)}</span>
            <span>{s.group_key ?? "single log"}</span>
            <span>{s.raw_logs.length} event{s.raw_logs.length === 1 ? "" : "s"}</span>
            <span>created {absoluteTime(s.created_at)}</span>
            <span>pipeline {duration(d.summary.pipeline_seconds)}</span>
          </p>
        </div>
        <MitreChips ids={s.triage?.mitre_techniques ?? []} names={mitreNames} />
      </header>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <Section title="Agent timeline">
          <ol>
            <Step icon={Microscope} title="Triage" state={stepState("triage")} meta={ran("triage") && duration(timing.triage)}>
              {s.triage && <>
                <p className="text-sm text-muted">{s.triage.triage_summary}</p>
                <KV k="Classified as">{vectorLabel(s.triage.attack_vector)} <span className="text-faint">· confidence {pct(s.triage.triage_confidence)}</span></KV>
                <KV k="Log format">{s.triage.discovered_layout}</KV>
                <div>
                  <p className="label mb-1">Indicators ({s.triage.iocs.length})</p>
                  <div className="flex flex-wrap gap-1.5">
                    {s.triage.iocs.length ? s.triage.iocs.map((i) => (
                      <span key={i.ioc_type + i.value} className="rounded border border-line bg-raised px-2 py-0.5 text-xs">
                        <span className="text-faint">{i.ioc_type.replace("_", " ").toLowerCase()}</span>{" "}
                        <span className="font-mono text-fg">{i.value}</span>
                      </span>
                    )) : <span className="text-xs text-faint">none extracted</span>}
                  </div>
                  {!!s.triage.dropped_iocs?.length && (
                    <details className="mt-1.5 text-xs text-faint">
                      <summary className="cursor-pointer">{s.triage.dropped_iocs.length} candidate(s) rejected by validation</summary>
                      <ul className="mt-1 list-disc pl-5 font-mono">{s.triage.dropped_iocs.map((x) => <li key={x}>{x}</li>)}</ul>
                    </details>
                  )}
                </div>
              </>}
            </Step>

            <Step icon={Search} title={s.forensics?.mode === "agent" ? "Forensics agent" : "Forensics (RAG)"}
                  state={stepState("forensics")} meta={ran("forensics") && duration(timing.forensics)}>
              {s.forensics && <>
                <ScoreBar value={s.forensics.final_similarity_score} threshold={d.threshold}
                          label={`Similarity to ${s.forensics.best_playbook || "best playbook"} (threshold ${d.threshold})`} />
                <p className="text-xs text-muted">{s.forensics.rag_timeline_notes}</p>
                {s.forensics.agent_rationale && <KV k="Agent rationale">{s.forensics.agent_rationale}</KV>}
                {s.forensics.intel_hits.length > 0 && (
                  <div className="rounded-md border border-crit/40 bg-crit/5 px-3 py-2">
                    <p className="label mb-1 flex items-center gap-1.5"><ShieldAlert className="h-3.5 w-3.5 text-crit" /> Threat-intel matches</p>
                    <ul className="space-y-0.5 text-xs">
                      {s.forensics.intel_hits.map((h, i) => (
                        <li key={i}><span className="font-mono text-fg">{h.ioc}</span> <span className="text-muted">— {h.severity} · {h.description} ({h.source})</span></li>
                      ))}
                    </ul>
                  </div>
                )}
                <Trace steps={s.forensics_trace ?? []} />
                {forensicsMissed && (
                  <p className="flex items-center gap-1.5 text-sm text-fg">
                    <ShieldAlert aria-hidden className="h-4 w-4 text-crit" />
                    No playbook cleared the threshold: escalated straight to a human, no automated plan.
                  </p>
                )}
              </>}
            </Step>

            <Step icon={Zap} title="Containment plan" state={stepState("neutralizer", forensicsMissed)}
                  meta={ran("neutralizer") && duration(timing.neutralizer)}>
              {s.action_plan && <>
                <p className="text-base font-semibold text-fg">
                  {actionLabel(s.action_plan.action_type)}{" "}
                  {s.action_plan.target !== "none" && <span className="font-mono text-accent">{s.action_plan.target}</span>}
                </p>
                <p className="text-sm text-muted">{s.action_plan.justification}</p>
                <KV k="Grounding">
                  {s.action_plan.grounded
                    ? <span className="inline-flex items-center gap-1"><Check className="h-3.5 w-3.5 text-ok" /> {s.action_plan.grounding_note || "passed"}</span>
                    : <span className="inline-flex items-center gap-1"><XCircle className="h-3.5 w-3.5 text-crit" /> {s.action_plan.grounding_note}</span>}
                </KV>
                {s.corroboration?.applies && <CorroborationBox corr={s.corroboration} />}
                <KV k="HMAC seal"><span className="break-all font-mono text-xs text-muted">{s.action_plan.payload_hash}</span></KV>
              </>}
            </Step>

            <Step icon={Gavel} title="Human decision"
                  state={awaiting ? "active" : ran("hitl_gate_node") ? "done" : forensicsMissed || s.error ? "skipped" : "pending"}
                  meta={ran("hitl_gate_node") ? `waited ${duration(timing.hitl_gate_node)}` : awaiting ? "waiting for operator" : undefined}>
              {ran("hitl_gate_node") && (
                <KV k="Decision">{s.hitl_decision}{s.hitl_operator_note && <span className="text-muted"> — “{s.hitl_operator_note}”</span>}</KV>
              )}
            </Step>

            <Step icon={ShieldCheck} title="Execution"
                  state={ran("execute_action") ? (s.execution_result?.success ? "done" : "failed")
                    : ran("generate_report") || s.error ? "skipped" : "pending"}
                  meta={ran("execute_action") && duration(timing.execute_action)}>
              {s.execution_result && <>
                <KV k="Result">{s.execution_result.success ? "Succeeded" : "Failed"} · {s.execution_result.dry_run ? "dry-run" : "live"} · hash {s.execution_result.hash_verified ? "verified" : "MISMATCH"}</KV>
                {s.execution_result.error_message && <ErrorNote error={s.execution_result.error_message} />}
              </>}
            </Step>

            <Step icon={FileText} title="Report" state={ran("generate_report") ? "done" : "pending"} last
                  meta={ran("generate_report") && duration(timing.generate_report)} />
          </ol>
        </Section>

        <aside className="space-y-5 lg:sticky lg:top-20 lg:self-start">
          {awaiting && s.action_plan ? <DecisionPanel d={d} now={now} /> : <OutcomePanel d={d} />}
          {s.forensics && (
            <Section title={<span className="flex items-center gap-2"><BookOpen className="h-4 w-4" /> Playbook evidence</span>}>
              <ul className="space-y-2.5">
                {s.forensics.matches.slice(0, 4).map((m, i) => (
                  <li key={i}><ScoreBar value={m.similarity_score} threshold={d.threshold} label={m.playbook_id} /></li>
                ))}
              </ul>
            </Section>
          )}
        </aside>
      </div>

      <Section title={`Raw logs (${lines.length})`}>
        <LogViewer lines={lines} iocs={s.triage?.iocs ?? []} />
      </Section>

      {s.report_path && (
        <Section title="Incident report"
                 action={reportQ.data && <button className="btn-ghost px-2 py-1 text-xs" onClick={downloadReport}><Download className="h-3.5 w-3.5" /> Markdown</button>}>
          {reportQ.isLoading ? <Spinner label="Loading report" /> : reportQ.data ? <Markdown>{reportQ.data.markdown}</Markdown>
            : <ErrorNote error={reportQ.error ?? "Report unavailable"} />}
        </Section>
      )}

      <Section title="Audit trail">
        {auditQ.data?.length ? (
          <ol className="space-y-1.5 text-xs">
            {auditQ.data.map((a, i) => (
              <li key={i} className="flex flex-wrap gap-x-3">
                <span className="w-36 shrink-0 font-mono text-faint">{absoluteTime(a.ts)}</span>
                <span className="font-medium text-fg">{a.event}</span>
                <span className="text-muted">by {a.actor}</span>
                {"decision" in a && <span className="text-muted">{String(a.decision)}</span>}
                {"note" in a && a.note ? <span className="text-muted">“{String(a.note)}”</span> : null}
              </li>
            ))}
          </ol>
        ) : <p className="text-xs text-faint">No audit records for this incident yet.</p>}
      </Section>
    </div>
  );
}
