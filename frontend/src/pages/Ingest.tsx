import { useEffect, useRef, useState, type DragEvent } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, FileUp, Filter, Layers, Loader2, Play, XCircle } from "lucide-react";
import { api, type Job } from "../lib/api";
import { shortId } from "../lib/format";
import { EmptyState, ErrorNote, Kpi, Section } from "../components/ui";

const DELIMITERS = [
  { value: "", label: "Auto-detect" },
  { value: ",", label: "Comma (,)" },
  { value: ";", label: "Semicolon (;)" },
  { value: "\\t", label: "Tab" },
  { value: "|", label: "Pipe (|)" },
];

const MAX_BYTES = 5_000_000;

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(id);
  }, [value, ms]);
  return v;
}

function JobProgress({ jobId }: { jobId: string }) {
  const q = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.job(jobId),
    refetchInterval: (query) => (["done", "failed"].includes(query.state.data?.status ?? "") ? false : 2000),
  });
  const job: Job | undefined = q.data;
  if (!job) return <div className="text-sm text-muted">Starting…</div>;
  const total = job.total_groups ?? 0;
  const pctDone = total ? Math.round((job.completed / total) * 100) : job.status === "done" ? 100 : 0;
  const running = job.status === "screening" || job.status === "running";

  return (
    <Section title={
      <span className="flex items-center gap-2">
        {running ? <Loader2 className="h-4 w-4 animate-spin text-accent" />
          : job.status === "done" ? <CheckCircle2 className="h-4 w-4 text-ok" /> : <XCircle className="h-4 w-4 text-crit" />}
        {running ? "Agents are working…" : job.status === "done" ? "Batch complete" : "Batch failed"}
      </span>}>
      <div className="space-y-3">
        <div>
          <div className="mb-1 flex justify-between text-xs text-muted">
            <span>{job.completed} of {total || "?"} incident{total === 1 ? "" : "s"} processed</span>
            <span className="tabular-nums">{pctDone}%</span>
          </div>
          <div className="h-2 rounded-full bg-line/60" role="progressbar" aria-valuenow={pctDone} aria-valuemin={0} aria-valuemax={100}>
            <div className="h-2 rounded-full bg-accent transition-all" style={{ width: `${pctDone}%` }} />
          </div>
          {running && <p className="mt-1.5 text-xs text-faint">Each incident runs triage, a forensics agent and planning on the local model; expect about a minute per incident.</p>}
        </div>
        {job.error && <ErrorNote error={job.error} />}
        {job.incidents.length > 0 && (
          <ul className="divide-y divide-line rounded-md border border-line">
            {job.incidents.map((i) => (
              <li key={i.incident_id}>
                <Link to={`/incidents/${i.incident_id}`} className="flex flex-wrap items-center gap-x-3 px-3 py-2 text-sm hover:bg-raised/50">
                  <span className="font-mono text-xs text-muted">#{shortId(i.incident_id)}</span>
                  <span className="text-fg">{i.group_key}</span>
                  <span className="text-xs text-faint">{i.line_count} lines</span>
                  <span className="ml-auto text-xs text-muted">{i.phase_reached === "AWAITING_HITL" ? "Awaiting your approval" : i.threat_status}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}

export default function IngestPage() {
  const [text, setText] = useState("");
  const [filename, setFilename] = useState<string | null>(null);
  const [delimiter, setDelimiter] = useState("");
  const [dragging, setDragging] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const samples = useQuery({ queryKey: ["samples"], queryFn: api.samples, staleTime: Infinity });
  const debounced = useDebounced(text, 400);
  const preview = useQuery({
    queryKey: ["preview", debounced, delimiter],
    queryFn: () => api.preview(debounced, delimiter || null),
    enabled: debounced.trim().length > 0,
  });
  const submit = useMutation({
    mutationFn: () => api.ingestFile(text, delimiter || null, filename),
    onSuccess: (job) => setJobId(job.job_id),
  });

  const loadFile = async (file: File) => {
    setFileError(null);
    if (file.size > MAX_BYTES) {
      setFileError(`${file.name} is ${(file.size / 1e6).toFixed(1)} MB; the limit is 5 MB.`);
      return;
    }
    setText(await file.text());
    setFilename(file.name);
    setJobId(null);
  };
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) void loadFile(f);
  };
  const loadSample = async (name: string) => {
    if (!name) return;
    const s = await api.sample(name);
    setText(s.text);
    setFilename(s.name);
    setJobId(null);
  };

  const p = preview.data;

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-fg">Ingest logs</h1>
        <p className="text-sm text-muted">
          Logs are screened by deterministic rules first. Only suspicious, grouped activity reaches the agents, and the preview below costs no LLM time.
        </p>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Section title="Source">
          <div className="space-y-3">
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className={`flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-4 py-6 text-center transition-colors ${
                dragging ? "border-accent bg-accent/5" : "border-line"}`}>
              <FileUp aria-hidden className="h-6 w-6 text-faint" />
              <p className="text-sm text-fg">Drop a .log, .txt, .csv or .json file</p>
              <button className="btn-ghost" onClick={() => fileInput.current?.click()}>Choose file</button>
              <input ref={fileInput} type="file" accept=".log,.txt,.csv,.json,.jsonl" className="hidden"
                     onChange={(e) => e.target.files?.[0] && void loadFile(e.target.files[0])} />
              {filename && <p className="font-mono text-xs text-muted">{filename}</p>}
            </div>
            {fileError && <ErrorNote error={fileError} />}

            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block">
                <span className="label">Or load a bundled sample</span>
                <select className="input mt-1" defaultValue="" onChange={(e) => void loadSample(e.target.value)}>
                  <option value="">Choose a sample…</option>
                  {samples.data?.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
                </select>
              </label>
              <label className="block">
                <span className="label">Column delimiter</span>
                <select className="input mt-1" value={delimiter} onChange={(e) => setDelimiter(e.target.value)}>
                  {DELIMITERS.map((d) => <option key={d.label} value={d.value}>{d.label}</option>)}
                </select>
              </label>
            </div>

            <label className="block">
              <span className="label">Or paste log lines</span>
              <textarea className="input mt-1 h-48 resize-y font-mono text-xs" spellCheck={false} value={text}
                        onChange={(e) => { setText(e.target.value); setFilename(null); setJobId(null); }}
                        placeholder="2026-06-23T22:00:01Z AUTH failed login for user admin from 10.0.4.17" />
            </label>

            {submit.isError && <ErrorNote error={submit.error} />}
            <button className="btn-primary w-full" disabled={!p || p.groups.length === 0 || submit.isPending || !!jobId}
                    onClick={() => submit.mutate()}>
              {submit.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {p && p.groups.length > 0
                ? `Send ${p.groups.length} incident${p.groups.length === 1 ? "" : "s"} to the agents`
                : "Nothing suspicious to send yet"}
            </button>
          </div>
        </Section>

        <div className="space-y-5">
          {jobId && <JobProgress jobId={jobId} />}
          <Section title="Pre-screen preview">
            {!text.trim() ? (
              <EmptyState icon={Filter} title="Load some logs to preview">
                You'll see which lines the rules flag and how they group into incidents before any model runs.
              </EmptyState>
            ) : preview.isError ? <ErrorNote error={preview.error} /> : !p ? (
              <div className="flex items-center gap-2 text-sm text-muted"><Loader2 className="h-4 w-4 animate-spin" /> Screening…</div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-2">
                  <Kpi label="Lines" value={p.total_lines} />
                  <Kpi label="Flagged" value={p.suspicious_lines} hint={`${p.filtered_out_pct}% filtered out`} />
                  <Kpi label="Incidents" value={p.groups.length} icon={Layers} />
                </div>
                {p.groups.length > 0 && (
                  <div>
                    <p className="label mb-1.5">Incidents that will be created</p>
                    <ul className="flex flex-wrap gap-1.5">
                      {p.groups.map((g, i) => (
                        <li key={i} className="rounded-md border border-line bg-raised px-2 py-1 text-xs">
                          <span className="font-mono text-fg">{g.group_key}</span> <span className="text-faint">· {g.line_count} lines</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="max-h-80 overflow-auto rounded-md border border-line">
                  <table className="w-full min-w-[34rem] text-xs">
                    <thead className="sticky top-0 bg-surface">
                      <tr className="border-b border-line text-left">
                        <th className="label px-2 py-1.5">Flag</th>
                        <th className="label px-2 py-1.5">Line</th>
                        <th className="label px-2 py-1.5">Rule</th>
                      </tr>
                    </thead>
                    <tbody>
                      {p.lines.map((l, i) => (
                        <tr key={i} className={`border-b border-line/50 ${l.suspicious ? "bg-med/5" : ""}`}>
                          <td className="px-2 py-1 text-center">
                            {l.suspicious ? <span title="flagged" className="text-med">●</span> : <span className="text-faint">·</span>}
                            <span className="sr-only">{l.suspicious ? "flagged" : "benign"}</span>
                          </td>
                          <td className="max-w-[28rem] truncate px-2 py-1 font-mono text-muted" title={l.raw_text}>{l.raw_text}</td>
                          <td className="whitespace-nowrap px-2 py-1 text-faint">{l.reason ?? (l.success_login ? "success login (context)" : "")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {p.truncated && <p className="text-xs text-faint">Preview shows the first 500 lines; all lines will be processed.</p>}
              </div>
            )}
          </Section>
        </div>
      </div>
    </div>
  );
}
