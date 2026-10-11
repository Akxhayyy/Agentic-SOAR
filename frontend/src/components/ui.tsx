import { useMemo, useState, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  AlertOctagon, CheckCircle2, CircleDot, Hand, Loader2, ShieldCheck, XCircle, type LucideIcon,
} from "lucide-react";
import type { IOC, ThreatStatus } from "../lib/api";
import { clock, vectorLabel } from "../lib/format";

/* ------------------------------------------------------------------ status */

type StatusKey = ThreatStatus | "AWAITING" | "FAILED" | "RUNNING";

const STATUS: Record<StatusKey, { label: string; icon: LucideIcon; tone: string }> = {
  CONTAINED: { label: "Contained", icon: ShieldCheck, tone: "text-ok" },
  ESCALATED: { label: "Escalated", icon: AlertOctagon, tone: "text-crit" },
  OPEN: { label: "Open", icon: CircleDot, tone: "text-med" },
  CLOSED: { label: "Closed", icon: CheckCircle2, tone: "text-info" },
  AWAITING: { label: "Awaiting approval", icon: Hand, tone: "text-hitl" },
  FAILED: { label: "Failed", icon: XCircle, tone: "text-crit" },
  RUNNING: { label: "Running", icon: Loader2, tone: "text-accent" },
};

export function statusKey(s: { threat_status?: string | null; awaiting_hitl?: boolean; current_phase?: string | null }): StatusKey {
  if (s.awaiting_hitl) return "AWAITING";
  if (s.current_phase === "FAILED") return "FAILED";
  if (s.current_phase && !["REPORTED", "FAILED"].includes(s.current_phase) && s.current_phase !== "AWAITING_HITL") {
    return "RUNNING";
  }
  return (s.threat_status as ThreatStatus) ?? "OPEN";
}

/** Icon + label, never colour alone. Text stays in ink tokens; only the icon carries hue. */
export function StatusBadge({ status, size = "sm" }: { status: StatusKey; size?: "sm" | "md" }) {
  const s = STATUS[status];
  const Icon = s.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-raised ${
      size === "md" ? "px-2.5 py-1 text-sm" : "px-2 py-0.5 text-xs"} font-medium text-fg`}>
      <Icon aria-hidden className={`${size === "md" ? "h-4 w-4" : "h-3.5 w-3.5"} ${s.tone} ${status === "RUNNING" ? "animate-spin" : ""}`} />
      {s.label}
    </span>
  );
}

export function VectorTag({ vector }: { vector?: string | null }) {
  return <span className="text-sm text-fg">{vectorLabel(vector)}</span>;
}

export function MitreChips({ ids, names }: { ids: string[]; names?: Record<string, string> }) {
  if (!ids?.length) return <span className="text-xs text-faint">No ATT&CK tags</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {ids.map((id) => (
        <span key={id} title={names?.[id] ?? id}
              className="rounded border border-line bg-raised px-1.5 py-0.5 font-mono text-2xs text-muted">
          {id}
        </span>
      ))}
    </span>
  );
}

/* ------------------------------------------------------------------ layout bits */

export function Section({ title, action, children, className = "" }:
  { title: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
        <h2 className="text-sm font-semibold text-fg">{title}</h2>
        {action}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Kpi({ label, value, hint, icon: Icon, tone = "text-muted" }:
  { label: string; value: ReactNode; hint?: ReactNode; icon?: LucideIcon; tone?: string }) {
  return (
    <div className="card px-4 py-3">
      <div className="flex items-center justify-between">
        <span className="label">{label}</span>
        {Icon && <Icon aria-hidden className={`h-4 w-4 ${tone}`} />}
      </div>
      <div className="mt-1 text-2xl font-semibold tabular-nums text-fg">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-faint">{hint}</div>}
    </div>
  );
}

export function EmptyState({ icon: Icon, title, children }: { icon: LucideIcon; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <Icon aria-hidden className="h-8 w-8 text-faint" />
      <p className="text-sm font-medium text-fg">{title}</p>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="flex items-start gap-2 rounded-md border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-fg">
      <XCircle aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-crit" />
      <span>{msg}</span>
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-8 text-sm text-muted" role="status">
      <Loader2 aria-hidden className="h-4 w-4 animate-spin" /> {label}…
    </div>
  );
}

/* ------------------------------------------------------------------ score bar */

/** Similarity vs. the deterministic routing threshold (single value, marker line at threshold). */
export function ScoreBar({ value, threshold, label }: { value: number; threshold: number; label?: string }) {
  const cleared = value >= threshold;
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between text-xs">
        <span className="text-muted">{label}</span>
        <span className="font-mono tabular-nums text-fg">{value.toFixed(3)}</span>
      </div>
      <div className="relative h-2 rounded-full bg-line/70" role="meter" aria-valuemin={0} aria-valuemax={1}
           aria-valuenow={value} aria-label={`${label ?? "score"} ${value.toFixed(2)}, threshold ${threshold}`}>
        <div className={`h-2 rounded-full ${cleared ? "bg-accent" : "bg-faint"}`} style={{ width: `${Math.min(100, value * 100)}%` }} />
        <div className="absolute -top-1 h-4 w-0.5 rounded bg-fg/70" style={{ left: `${threshold * 100}%` }} title={`threshold ${threshold}`} />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ countdown */

export function CountdownRing({ remaining, total }: { remaining: number; total: number }) {
  const r = 26;
  const c = 2 * Math.PI * r;
  const frac = Math.max(0, Math.min(1, remaining / total));
  const urgent = remaining < 60;
  return (
    <div className="relative h-16 w-16 shrink-0" role="timer" aria-label={`${Math.round(remaining)} seconds until auto-escalation`}>
      <svg viewBox="0 0 64 64" className="h-16 w-16 -rotate-90">
        <circle cx="32" cy="32" r={r} fill="none" strokeWidth="4" className="stroke-line" />
        <circle cx="32" cy="32" r={r} fill="none" strokeWidth="4" strokeLinecap="round"
                className={urgent ? "stroke-crit" : "stroke-hitl"}
                strokeDasharray={c} strokeDashoffset={c * (1 - frac)} style={{ transition: "stroke-dashoffset 1s linear" }} />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center font-mono text-sm font-medium tabular-nums text-fg">
        {clock(remaining)}
      </span>
    </div>
  );
}

/* ------------------------------------------------------------------ markdown (safe) */

/**
 * Report / playbook rendering. react-markdown escapes raw HTML by default and
 * we deliberately do NOT enable rehype-raw: report text is partly LLM output
 * derived from attacker-controlled logs (THREAT_MODEL.md T8).
 */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="text-sm leading-relaxed text-fg">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: (p) => <h1 className="mb-3 mt-1 text-lg font-semibold" {...p} />,
          h2: (p) => <h2 className="mb-2 mt-5 text-base font-semibold" {...p} />,
          h3: (p) => <h3 className="mb-1.5 mt-4 text-sm font-semibold" {...p} />,
          p: (p) => <p className="my-2 text-muted" {...p} />,
          ul: (p) => <ul className="my-2 list-disc space-y-1 pl-5 text-muted" {...p} />,
          ol: (p) => <ol className="my-2 list-decimal space-y-1 pl-5 text-muted" {...p} />,
          code: (p) => <code className="rounded bg-raised px-1 py-0.5 font-mono text-[0.8em] text-fg" {...p} />,
          blockquote: (p) => <blockquote className="my-3 border-l-2 border-crit pl-3 text-fg" {...p} />,
          a: ({ href, children }) => <span title={href}>{children}</span>, // no outbound links from report text
          table: (p) => <div className="my-3 overflow-x-auto"><table className="w-full border-collapse text-xs" {...p} /></div>,
          th: (p) => <th className="border-b border-line px-2 py-1.5 text-left font-medium text-faint" {...p} />,
          td: (p) => <td className="border-b border-line/60 px-2 py-1.5 align-top text-fg" {...p} />,
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}

/* ------------------------------------------------------------------ log viewer */

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Raw log lines with extracted IOCs highlighted — rendered as text nodes, never HTML. */
export function LogViewer({ lines, iocs, maxHeight = "18rem" }: { lines: string[]; iocs: IOC[]; maxHeight?: string }) {
  const re = useMemo(() => {
    const values = [...new Set(iocs.map((i) => i.value))].filter(Boolean).sort((a, b) => b.length - a.length);
    return values.length ? new RegExp(`(${values.map(escapeRe).join("|")})`, "gi") : null;
  }, [iocs]);
  const typeOf = (v: string) => iocs.find((i) => i.value.toLowerCase() === v.toLowerCase())?.ioc_type;

  return (
    <div className="overflow-auto rounded-md border border-line bg-bg" style={{ maxHeight }}>
      <ol className="min-w-max py-2 font-mono text-xs leading-5">
        {lines.map((line, i) => (
          <li key={i} className="flex gap-3 px-3 hover:bg-raised/60">
            <span className="w-6 shrink-0 select-none text-right text-faint">{i + 1}</span>
            <span className="whitespace-pre text-muted">
              {re
                ? line.split(re).map((part, j) =>
                    j % 2 === 1 ? (
                      <mark key={j} title={typeOf(part)} className="rounded bg-accent/20 px-0.5 text-fg">{part}</mark>
                    ) : (
                      <span key={j}>{part}</span>
                    ))
                : line}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

/* ------------------------------------------------------------------ charts */

/**
 * Single-series horizontal bar list (magnitude by category). One hue, no
 * legend (the section title names the series), labels + values always
 * visible so the list doubles as its own table view, per-bar hover tooltip.
 */
export function BarList({ data, total, formatLabel = (k: string) => k }:
  { data: { key: string; value: number }[]; total?: number; formatLabel?: (k: string) => string }) {
  const [hover, setHover] = useState<string | null>(null);
  const max = Math.max(1, ...data.map((d) => d.value));
  const sum = total ?? data.reduce((a, d) => a + d.value, 0);
  if (!data.length) return <p className="py-4 text-sm text-faint">No data yet.</p>;
  return (
    <ul className="space-y-2.5">
      {data.map((d) => (
        <li key={d.key} className="relative" onMouseEnter={() => setHover(d.key)} onMouseLeave={() => setHover(null)}>
          <div className="mb-1 flex justify-between text-xs">
            <span className="text-fg">{formatLabel(d.key)}</span>
            <span className="font-mono tabular-nums text-muted">{d.value}</span>
          </div>
          <div className="h-2 rounded-full bg-line/50">
            <div className={`h-2 rounded-full transition-colors ${hover === d.key ? "bg-accent" : "bg-accent/80"}`}
                 style={{ width: `${(d.value / max) * 100}%` }} />
          </div>
          {hover === d.key && (
            <div className="pointer-events-none absolute right-0 top-[-1.9rem] z-10 rounded-md border border-line bg-raised px-2 py-1 text-xs text-fg shadow-lg">
              {formatLabel(d.key)}: <b>{d.value}</b> ({sum ? Math.round((d.value / sum) * 100) : 0}%)
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

/** Single-series daily column chart with a hover tooltip per column. */
export function DailyColumns({ data }: { data: { day: string; value: number }[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...data.map((d) => d.value));
  const W = 560, H = 120, gap = 2;
  const bw = data.length ? (W - gap * (data.length - 1)) / data.length : 0;
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H + 18}`} className="w-full" role="img" aria-label="Incidents per day">
        <line x1="0" x2={W} y1={H} y2={H} className="stroke-line" strokeWidth="1" />
        {data.map((d, i) => {
          const h = (d.value / max) * (H - 8);
          const x = i * (bw + gap);
          const rr = Math.min(4, h, bw / 2);
          return (
            <g key={d.day} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
              <rect x={x} y={0} width={bw} height={H} fill="transparent" />
              {d.value > 0 && (
                <path className={hover === i ? "fill-accent" : "fill-accent/80"}
                      d={`M${x},${H} V${H - h + rr} Q${x},${H - h} ${x + rr},${H - h} H${x + bw - rr} Q${x + bw},${H - h} ${x + bw},${H - h + rr} V${H} Z`} />
              )}
              {(i === 0 || i === data.length - 1 || i % 7 === 0) && (
                <text x={x + bw / 2} y={H + 13} textAnchor="middle" className="fill-faint text-[10px]">{d.day.slice(5)}</text>
              )}
            </g>
          );
        })}
      </svg>
      {hover != null && data[hover] && (
        <div className="pointer-events-none absolute top-0 rounded-md border border-line bg-raised px-2 py-1 text-xs text-fg shadow-lg"
             style={{ left: `${Math.min(80, (hover / Math.max(1, data.length)) * 100)}%` }}>
          {data[hover].day}: <b>{data[hover].value}</b> incident{data[hover].value === 1 ? "" : "s"}
        </div>
      )}
    </div>
  );
}
