import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AlertOctagon, Clock3, Hand, Inbox, Search, ShieldCheck, Upload } from "lucide-react";
import { api, type IncidentSummary } from "../lib/api";
import { actionLabel, clock, duration, shortId, timeAgo, vectorLabel } from "../lib/format";
import { useNow } from "../lib/events";
import {
  BarList, DailyColumns, EmptyState, ErrorNote, Kpi, MitreChips, Section, Spinner, StatusBadge, statusKey,
} from "../components/ui";

const FILTERS = [
  { key: "all", label: "All" },
  { key: "awaiting", label: "Awaiting approval" },
  { key: "ESCALATED", label: "Escalated" },
  { key: "OPEN", label: "Open" },
  { key: "CONTAINED", label: "Contained" },
  { key: "CLOSED", label: "Closed" },
] as const;

function median(xs: number[]): number | null {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function matches(i: IncidentSummary, filter: string, q: string): boolean {
  if (filter === "awaiting" && !i.awaiting_hitl) return false;
  if (!["all", "awaiting"].includes(filter) && (i.awaiting_hitl || i.threat_status !== filter)) return false;
  if (!q) return true;
  const hay = [i.incident_id, i.group_key, i.attack_vector, i.action_target, i.playbook, ...(i.mitre_techniques ?? [])]
    .join(" ").toLowerCase();
  return hay.includes(q.toLowerCase());
}

export default function IncidentsPage() {
  const [params, setParams] = useSearchParams();
  const filter = params.get("filter") ?? "all";
  const [q, setQ] = useState("");
  const now = useNow(1000);
  const navigate = useNavigate();
  const query = useQuery({ queryKey: ["incidents"], queryFn: api.incidents, refetchInterval: 30000 });
  const incidents = query.data ?? [];
  const fetchedAt = query.dataUpdatedAt;

  const stats = useMemo(() => {
    const by = (s: string) => incidents.filter((i) => !i.awaiting_hitl && i.threat_status === s).length;
    const vectors: Record<string, number> = {};
    const days: Record<string, number> = {};
    for (const i of incidents) {
      if (i.attack_vector) vectors[i.attack_vector] = (vectors[i.attack_vector] ?? 0) + 1;
      if (i.created_at) days[i.created_at.slice(0, 10)] = (days[i.created_at.slice(0, 10)] ?? 0) + 1;
    }
    const today = new Date().setHours(12, 0, 0, 0);
    const daily = Array.from({ length: 14 }, (_, k) => {
      const d = new Date(today - (13 - k) * 86400000).toISOString().slice(0, 10);
      return { day: d, value: days[d] ?? 0 };
    });
    return {
      awaiting: incidents.filter((i) => i.awaiting_hitl).length,
      open: by("OPEN"),
      escalated: by("ESCALATED"),
      contained: by("CONTAINED"),
      medianPipeline: median(incidents.filter((i) => i.pipeline_seconds > 0).map((i) => i.pipeline_seconds)),
      vectors: Object.entries(vectors).map(([key, value]) => ({ key, value })).sort((a, b) => b.value - a.value),
      daily,
    };
  }, [incidents]);

  const awaiting = incidents.filter((i) => i.awaiting_hitl);
  const rows = incidents.filter((i) => matches(i, filter, q));
  const remaining = (i: IncidentSummary) =>
    i.hitl_timeout_remaining_seconds == null ? null : Math.max(0, i.hitl_timeout_remaining_seconds - (now - fetchedAt) / 1000);

  if (query.isLoading) return <Spinner label="Loading incidents" />;

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-fg">Incidents</h1>
          <p className="text-sm text-muted">Every incident the agent pipeline has handled, newest first.</p>
        </div>
        <Link to="/ingest" className="btn-primary"><Upload className="h-4 w-4" /> Ingest logs</Link>
      </div>

      {query.isError && <ErrorNote error={query.error} />}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Kpi label="Awaiting approval" value={stats.awaiting} icon={Hand} tone="text-hitl" />
        <Kpi label="Escalated" value={stats.escalated} icon={AlertOctagon} tone="text-crit" />
        <Kpi label="Open" value={stats.open} icon={Inbox} tone="text-med" />
        <Kpi label="Contained" value={stats.contained} icon={ShieldCheck} tone="text-ok" />
        <Kpi label="Median pipeline time" value={duration(stats.medianPipeline)} icon={Clock3}
             hint="ingest → plan, excluding human wait" />
      </div>

      {awaiting.length > 0 && (
        <Section title={<span className="flex items-center gap-2"><Hand className="h-4 w-4 text-hitl" /> Needs your decision</span>}>
          <ul className="divide-y divide-line">
            {awaiting.map((i) => {
              const r = remaining(i);
              return (
                <li key={i.incident_id}>
                  <Link to={`/incidents/${i.incident_id}`}
                        className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2.5 hover:bg-raised/40">
                    <span className={`w-14 font-mono text-sm tabular-nums ${r != null && r < 60 ? "text-crit" : "text-fg"}`}
                          aria-label="time left">{r != null ? clock(r) : "—"}</span>
                    <span className="text-sm font-medium text-fg">{actionLabel(i.action_type)}</span>
                    <span className="font-mono text-sm text-muted">{i.action_target}</span>
                    <span className="text-sm text-muted">{vectorLabel(i.attack_vector)}</span>
                    <span className="ml-auto text-xs text-faint">{i.group_key ?? shortId(i.incident_id)}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </Section>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        <Section title="Incidents by attack vector" className="lg:col-span-1">
          <BarList data={stats.vectors} formatLabel={vectorLabel} />
        </Section>
        <Section title="Incidents per day (last 14 days)" className="lg:col-span-2">
          <DailyColumns data={stats.daily} />
        </Section>
      </div>

      <section className="card">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5">
          <div role="tablist" aria-label="Filter incidents" className="flex flex-wrap gap-1">
            {FILTERS.map((f) => (
              <button key={f.key} role="tab" aria-selected={filter === f.key}
                      onClick={() => setParams(f.key === "all" ? {} : { filter: f.key })}
                      className={`rounded-md px-2.5 py-1 text-xs font-medium ${
                        filter === f.key ? "bg-raised text-fg" : "text-muted hover:text-fg"}`}>
                {f.label}
              </button>
            ))}
          </div>
          <label className="relative ml-auto w-full sm:w-64">
            <span className="sr-only">Search incidents</span>
            <Search aria-hidden className="absolute left-2.5 top-2 h-4 w-4 text-faint" />
            <input className="input pl-8" placeholder="Search IP, user, ID, technique…" value={q}
                   onChange={(e) => setQ(e.target.value)} />
          </label>
        </div>

        {incidents.length === 0 ? (
          <EmptyState icon={Inbox} title="No incidents yet">
            Upload a log file or pick a bundled sample on the <Link className="text-accent underline" to="/ingest">Ingest</Link> page.
          </EmptyState>
        ) : rows.length === 0 ? (
          <EmptyState icon={Search} title="Nothing matches this filter" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[46rem] text-sm">
              <thead>
                <tr className="border-b border-line text-left">
                  {["Status", "Attack vector", "Containment", "Source", "ATT&CK", "Created"].map((h) => (
                    <th key={h} className="label px-4 py-2 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => (
                  <tr key={i.incident_id} tabIndex={0}
                      onClick={() => navigate(`/incidents/${i.incident_id}`)}
                      onKeyDown={(e) => e.key === "Enter" && navigate(`/incidents/${i.incident_id}`)}
                      className="cursor-pointer border-b border-line/60 last:border-0 hover:bg-raised/50">
                    <td className="px-4 py-2.5"><StatusBadge status={statusKey(i)} /></td>
                    <td className="px-4 py-2.5 text-fg">{vectorLabel(i.attack_vector)}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-fg">{actionLabel(i.action_type)}</span>
                      {i.action_target && i.action_target !== "none" && (
                        <span className="ml-1.5 font-mono text-xs text-muted">{i.action_target}</span>
                      )}
                      {i.rolled_back && <span className="ml-1.5 text-xs text-faint">(rolled back)</span>}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted">{i.group_key ?? shortId(i.incident_id)}</td>
                    <td className="px-4 py-2.5"><MitreChips ids={i.mitre_techniques} /></td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-xs text-muted" title={i.created_at ?? ""}>
                      {timeAgo(i.created_at, now)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
