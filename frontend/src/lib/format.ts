const VECTOR_LABELS: Record<string, string> = {
  BRUTE_FORCE_AUTH: "Brute force",
  NETWORK_INTRUSION: "Network intrusion",
  MALWARE_EXECUTION: "Malware execution",
  DATA_EXFILTRATION: "Data exfiltration",
  PRIVILEGE_ESCALATION: "Privilege escalation",
  PROXY_ANOMALY: "Proxy anomaly",
  UNKNOWN: "Unknown",
};

const ACTION_LABELS: Record<string, string> = {
  ISOLATE_HOST: "Isolate host",
  LOCK_ACCOUNT: "Lock account",
  QUARANTINE_PROCESS: "Quarantine process",
  TERMINATE_PROCESS: "Terminate process",
  BLOCK_PROXY_IP: "Block IP at proxy",
  NO_ACTION: "No action",
};

export const vectorLabel = (v?: string | null) => (v ? VECTOR_LABELS[v] ?? v : "—");
export const actionLabel = (a?: string | null) => (a ? ACTION_LABELS[a] ?? a : "—");
export const shortId = (id: string) => id.slice(0, 8);
export const pct = (v?: number | null, digits = 0) => (v == null ? "—" : `${(v * 100).toFixed(digits)}%`);

export function timeAgo(iso?: string | null, now = Date.now()): string {
  if (!iso) return "—";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function duration(seconds?: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const m = Math.floor(seconds / 60);
  return `${m}m ${Math.round(seconds % 60)}s`;
}

export function clock(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function absoluteTime(iso?: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

/** Seconds left before the HITL timeout, computed client-side from the persisted pause time. */
export function hitlRemaining(pausedAt: string | null | undefined, timeoutS: number, now = Date.now()): number | null {
  if (!pausedAt) return null;
  return Math.max(0, timeoutS - (now - new Date(pausedAt).getTime()) / 1000);
}
