import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

export interface LiveEvent {
  type: string;
  ts: string;
  incident_id?: string;
  node?: string;
  phase?: string;
  [key: string]: unknown;
}

const EVENT_TYPES = ["node_started", "node_finished", "hitl_waiting", "hitl_decided",
                     "incident_created", "incident_updated", "job_progress"];

/**
 * Subscribes to the backend's Server-Sent Events stream and invalidates the
 * matching React Query caches, so every page updates live without polling.
 * Returns connection state + the most recent events (for the activity feed).
 */
export function useLiveEvents(): { connected: boolean; recent: LiveEvent[] } {
  const qc = useQueryClient();
  const [connected, setConnected] = useState(false);
  const [recent, setRecent] = useState<LiveEvent[]>([]);

  useEffect(() => {
    const source = new EventSource("/api/events");
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false); // EventSource reconnects on its own

    const handle = (e: MessageEvent) => {
      let ev: LiveEvent;
      try {
        ev = JSON.parse(e.data);
      } catch {
        return;
      }
      setRecent((prev) => [ev, ...prev].slice(0, 30));
      if (ev.incident_id) qc.invalidateQueries({ queryKey: ["incident", ev.incident_id] });
      if (ev.type !== "node_started") qc.invalidateQueries({ queryKey: ["incidents"] });
      if (ev.type === "job_progress") qc.invalidateQueries({ queryKey: ["job"] });
      if (ev.type.startsWith("hitl")) qc.invalidateQueries({ queryKey: ["health"] });
    };
    EVENT_TYPES.forEach((t) => source.addEventListener(t, handle as EventListener));
    return () => source.close();
  }, [qc]);

  return { connected, recent };
}

/** Re-renders every `ms` — drives countdowns without refetching. */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), ms);
    return () => window.clearInterval(id);
  }, [ms]);
  return now;
}
