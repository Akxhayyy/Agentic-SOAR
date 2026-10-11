import { useEffect, useState } from "react";
import { NavLink, Outlet, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, BookOpen, FlaskConical, Hand, Inbox, Moon, Server, Shield, Sun, Upload,
} from "lucide-react";
import { api } from "../lib/api";
import { useLiveEvents } from "../lib/events";

const NAV = [
  { to: "/", label: "Incidents", icon: Inbox, end: true },
  { to: "/ingest", label: "Ingest", icon: Upload },
  { to: "/playbooks", label: "Playbooks", icon: BookOpen },
  { to: "/evaluation", label: "Evaluation", icon: FlaskConical },
  { to: "/system", label: "System", icon: Server },
];

function Pill({ ok, label, detail }: { ok: boolean | null; label: string; detail?: string }) {
  const dot = ok == null ? "bg-faint" : ok ? "bg-ok" : "bg-crit";
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-raised px-2 py-0.5 text-xs text-muted"
          title={detail}>
      <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${dot}`} />
      <span className="text-fg">{label}</span>
      <span className="sr-only">{ok == null ? "unknown" : ok ? "online" : "offline"}</span>
      {detail && <span className="hidden max-w-[10rem] truncate font-mono lg:inline">{detail}</span>}
    </span>
  );
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("soar-theme") ?? "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("soar-theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

export default function Layout() {
  const { connected } = useLiveEvents();
  const [theme, toggleTheme] = useTheme();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 15000 });
  const h = health.data;
  const modelPulled = h ? !h.ollama.missing.includes(h.reasoning_model) : null;

  return (
    <div className="flex min-h-full flex-col">
      <header className="sticky top-0 z-30 border-b border-line bg-bg/90 backdrop-blur"
              style={{ paddingTop: "env(safe-area-inset-top, 0px)" }}>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5">
          <Link to="/" className="flex items-center gap-2 font-semibold text-fg">
            <Shield aria-hidden className="h-5 w-5 text-accent" />
            Agentic SOAR
          </Link>

          {h && (
            <span className={`rounded-md px-2 py-0.5 text-xs font-semibold tracking-wide ${
              h.dry_run ? "border border-line bg-raised text-muted" : "border border-crit bg-crit/15 text-fg"}`}
                  title={h.dry_run ? "Actions are simulated (execution.dry_run = true)" : "LIVE: actions run real OS commands"}>
              {h.dry_run ? "DRY-RUN" : "LIVE"}
            </span>
          )}

          <div className="flex flex-wrap items-center gap-1.5">
            <Pill ok={health.isError ? false : h ? true : null} label="Backend" />
            <Pill ok={h ? h.ollama.online : null} label="Ollama" />
            <Pill ok={modelPulled} label="Model" detail={h?.reasoning_model} />
            <Pill ok={h ? h.playbook_chunks > 0 : null} label="RAG" detail={h ? `${h.playbook_chunks} chunks` : undefined} />
            <Pill ok={connected} label="Live" />
          </div>

          <div className="ml-auto flex items-center gap-2">
            {h && h.awaiting_hitl > 0 && (
              <Link to="/?filter=awaiting"
                    className="inline-flex items-center gap-1.5 rounded-full border border-hitl/60 bg-hitl/10 px-2.5 py-1 text-xs font-medium text-fg">
                <Hand aria-hidden className="h-3.5 w-3.5 text-hitl" />
                {h.awaiting_hitl} awaiting approval
              </Link>
            )}
            <button className="btn-ghost px-2" onClick={toggleTheme}
                    aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
          </div>
        </div>
        {h && modelPulled === false && (
          <div className="border-t border-med/40 bg-med/10 px-4 py-1.5 text-xs text-fg">
            The reasoning model <span className="font-mono">{h.reasoning_model}</span> is not pulled. Run{" "}
            <code className="font-mono">ollama pull {h.reasoning_model}</code> (or set SOAR_REASONING_MODEL) before ingesting.
          </div>
        )}
      </header>

      <div className="flex flex-1 flex-col md:flex-row">
        <nav aria-label="Main" className="border-b border-line md:w-52 md:shrink-0 md:border-b-0 md:border-r">
          <ul className="flex gap-1 overflow-x-auto px-3 py-2 md:flex-col md:px-2 md:py-4">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <li key={to}>
                <NavLink to={to} end={end}
                  className={({ isActive }) => `flex items-center gap-2.5 whitespace-nowrap rounded-md px-3 py-2 text-sm ${
                    isActive ? "bg-raised font-medium text-fg" : "text-muted hover:bg-raised/60 hover:text-fg"}`}>
                  <Icon aria-hidden className="h-4 w-4" />
                  {label}
                </NavLink>
              </li>
            ))}
          </ul>
          <div className="hidden px-4 pt-6 text-2xs text-faint md:block">
            <Activity aria-hidden className="mb-1 h-3.5 w-3.5" />
            Local-only · Ollama · LangGraph
          </div>
        </nav>
        <main className="min-w-0 flex-1 px-4 py-5 md:px-6" style={{ paddingBottom: "max(1.25rem, env(safe-area-inset-bottom, 0px))" }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
