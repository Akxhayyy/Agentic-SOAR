// Typed client for the FastAPI backend (main.py). All calls are same-origin
// (/api/...) — served by FastAPI in production, proxied by Vite in dev.

export type ThreatStatus = "OPEN" | "CONTAINED" | "ESCALATED" | "CLOSED";
export type Decision = "PENDING" | "APPROVED" | "REJECTED" | "TIMEOUT";

export interface IncidentSummary {
  incident_id: string;
  created_at: string | null;
  group_key: string | null;
  attack_vector: string | null;
  triage_confidence: number | null;
  mitre_techniques: string[];
  ioc_count: number;
  event_count: number;
  forensics_score: number | null;
  playbook: string | null;
  action_type: string | null;
  action_target: string | null;
  current_phase: string | null;
  threat_status: ThreatStatus | null;
  hitl_decision: Decision | null;
  awaiting_hitl: boolean;
  hitl_timeout_remaining_seconds: number | null;
  error: string | null;
  pipeline_seconds: number;
  rolled_back: boolean;
}

export interface IOC {
  ioc_type: string;
  value: string;
  confidence: number;
}

export interface PlaybookMatch {
  playbook_id: string;
  chunk_text: string;
  similarity_score: number;
}

export interface TraceStep {
  step: number;
  tool: string;
  args: Record<string, unknown>;
  result_summary: string;
  duration_ms: number;
  thought?: string;
}

export interface PhaseEntry {
  node: string;
  phase: string;
  started_at: string;
  ended_at: string;
  duration_s: number;
}

export interface IncidentState {
  incident_id: string;
  created_at: string;
  group_key: string | null;
  raw_logs: { raw_text: string; log_type: string; source: string }[];
  triage: {
    attack_vector: string;
    discovered_layout: string;
    iocs: IOC[];
    triage_summary: string;
    triage_confidence: number;
    mitre_techniques: string[];
    dropped_iocs?: string[];
    dropped_mitre?: string[];
  } | null;
  forensics: {
    matches: PlaybookMatch[];
    pass_count: number;
    final_similarity_score: number;
    cleared_threshold: boolean;
    rag_timeline_notes: string;
    best_playbook: string;
    rerank_reason: string;
    mode: "agent" | "two_pass";
    agent_confidence: number | null;
    agent_rationale: string;
    intel_hits: { ioc: string; indicator: string; type: string; severity: string; source: string; description: string }[];
    related_log_count: number;
    prior_incidents: string[];
  } | null;
  forensics_trace: TraceStep[];
  action_plan: {
    action_type: string;
    target: string;
    params: Record<string, string>;
    justification: string;
    payload_hash: string;
    grounded: boolean;
    grounding_note: string;
  } | null;
  execution_result: {
    action_type: string;
    target: string;
    dry_run: boolean;
    success: boolean;
    hash_verified: boolean;
    stub_response: Record<string, unknown>;
    executed_at: string;
    error_message: string | null;
  } | null;
  hitl_decision: Decision;
  hitl_operator_note: string | null;
  hitl_paused_at: string | null;
  threat_status: ThreatStatus;
  current_phase: string;
  phase_history: PhaseEntry[];
  report_path: string | null;
  error: string | null;
  rollback_result: { action: string; target: string; by: string; note: string | null; at: string } | null;
  corroboration: Corroboration | null;
  hitl_ack_uncorroborated?: boolean;
}

export interface Corroboration {
  applies: boolean;
  met: boolean;
  count: number;
  required: number;
  signals: { kind: string; detail: string }[];
}

export interface IncidentDetail {
  incident_id: string;
  summary: IncidentSummary;
  state: IncidentState;
  hitl_timeout_seconds: number;
  threshold: number;
  dry_run: boolean;
}

export interface Health {
  backend: boolean;
  ollama: { online: boolean; pulled: string[]; missing: string[]; loaded: { name: string; vram_bytes: number }[] };
  reasoning_model: string;
  embedding_model: string;
  num_ctx: number;
  playbook_chunks: number;
  dry_run: boolean;
  security: { grounding: boolean; deny_list: boolean; hash_check: boolean };
  hitl_timeout_seconds: number;
  gpu: { name: string; vram_total_mb: number; vram_used_mb: number } | null;
  awaiting_hitl: number;
}

export interface PreviewLine {
  raw_text: string;
  log_type: string;
  timestamp: string | null;
  ip: string | null;
  user: string | null;
  suspicious: boolean;
  reason: string | null;
  success_login: boolean;
}

export interface Preview {
  total_lines: number;
  suspicious_lines: number;
  filtered_out_pct: number;
  lines: PreviewLine[];
  truncated: boolean;
  groups: { group_key: string; line_count: number; log_type: string }[];
}

export interface Job {
  job_id: string;
  filename: string | null;
  status: "screening" | "running" | "done" | "failed";
  created_at: string;
  finished_at: string | null;
  total_lines: number | null;
  suspicious_lines: number | null;
  total_groups: number | null;
  completed: number;
  incidents: { incident_id: string; group_key: string; line_count: number; phase_reached: string; threat_status: string }[];
  error: string | null;
}

export interface Playbook {
  id: string;
  title: string;
  markdown: string;
}

export interface AuditRecord {
  ts: string;
  event: string;
  incident_id: string | null;
  actor: string;
  [key: string]: unknown;
}

export interface EvalResults {
  stamp: string;
  scenarios: number;
  skipped: string[];
  metrics: Record<string, Record<string, unknown>>;
}

export interface RedteamResults {
  stamp: string;
  summary: Record<string, {
    overall: Record<string, number | null>;
    by_class: Record<string, { payloads: number; asr_off: number | null; asr_on: number | null; blocked_by_on: Record<string, number> }>;
  }>;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body: unknown) => request<T>(path, { method: "POST", body: JSON.stringify(body) });

export const api = {
  health: () => request<Health>("/api/health"),
  incidents: () => request<IncidentSummary[]>("/api/incidents"),
  incident: (id: string) => request<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`),
  report: (id: string) => request<{ markdown: string }>(`/api/incidents/${encodeURIComponent(id)}/report`),
  incidentAudit: (id: string) => request<AuditRecord[]>(`/api/incidents/${encodeURIComponent(id)}/audit`),
  decide: (id: string, decision: "APPROVED" | "REJECTED", note: string, operator: string, acknowledgeUncorroborated = false) =>
    post<{ summary: IncidentSummary }>(`/api/incidents/${encodeURIComponent(id)}/decision`,
      { decision, note: note || null, operator, acknowledge_uncorroborated: acknowledgeUncorroborated }),
  rollback: (id: string, operator: string, note: string) =>
    post(`/api/incidents/${encodeURIComponent(id)}/rollback`, { operator, note: note || null }),
  preview: (file_text: string, delimiter: string | null) =>
    post<Preview>("/api/ingest_file/preview", { file_text, delimiter }),
  ingestFile: (file_text: string, delimiter: string | null, filename: string | null) =>
    post<Job>("/api/ingest_file", { file_text, delimiter, filename }),
  job: (id: string) => request<Job>(`/api/jobs/${encodeURIComponent(id)}`),
  jobs: () => request<Job[]>("/api/jobs"),
  samples: () => request<{ name: string; bytes: number }[]>("/api/samples"),
  sample: (name: string) => request<{ name: string; text: string }>(`/api/samples/${encodeURIComponent(name)}`),
  playbooks: () => request<Playbook[]>("/api/playbooks"),
  config: () => request<Record<string, any>>("/api/config"),
  audit: (limit = 100) => request<AuditRecord[]>(`/api/audit?limit=${limit}`),
  benchmark: () => post<Record<string, any>>("/api/system/benchmark", {}),
  evalLatest: () => request<EvalResults>("/api/eval/latest"),
  redteamLatest: () => request<RedteamResults>("/api/redteam/latest"),
};
