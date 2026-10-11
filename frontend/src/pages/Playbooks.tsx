import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { BookOpen } from "lucide-react";
import { api } from "../lib/api";
import { EmptyState, ErrorNote, Markdown, Section, Spinner } from "../components/ui";

export default function PlaybooksPage() {
  const books = useQuery({ queryKey: ["playbooks"], queryFn: api.playbooks, staleTime: Infinity });
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.incidents });
  const [selected, setSelected] = useState<string | null>(null);

  const usage = useMemo(() => {
    const u: Record<string, number> = {};
    for (const i of incidents.data ?? []) if (i.playbook) u[i.playbook] = (u[i.playbook] ?? 0) + 1;
    return u;
  }, [incidents.data]);

  if (books.isLoading) return <Spinner label="Loading playbooks" />;
  if (books.isError) return <ErrorNote error={books.error} />;
  const list = books.data ?? [];
  const current = list.find((b) => b.id === selected) ?? list[0];

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-fg">Playbooks</h1>
        <p className="text-sm text-muted">The response knowledge base the forensics agent retrieves from (embedded with nomic-embed-text into ChromaDB).</p>
      </div>
      {!list.length ? (
        <EmptyState icon={BookOpen} title="No playbooks found">Add Markdown files to config/playbooks and run python -m rag.ingest_playbooks.</EmptyState>
      ) : (
        <div className="grid gap-5 md:grid-cols-[16rem_minmax(0,1fr)]">
          <nav aria-label="Playbooks" className="card h-fit p-2">
            <ul className="space-y-0.5">
              {list.map((b) => (
                <li key={b.id}>
                  <button onClick={() => setSelected(b.id)} aria-current={current?.id === b.id}
                          className={`flex w-full items-center justify-between gap-2 rounded-md px-3 py-2 text-left text-sm ${
                            current?.id === b.id ? "bg-raised font-medium text-fg" : "text-muted hover:bg-raised/60 hover:text-fg"}`}>
                    <span className="truncate">{b.title.replace(/^Playbook:\s*/, "")}</span>
                    <span className="shrink-0 text-xs tabular-nums text-faint" title="incidents matched">{usage[b.id] ?? 0}</span>
                  </button>
                </li>
              ))}
            </ul>
          </nav>
          {current && (
            <Section title={<span className="font-mono text-xs text-muted">{current.id}</span>}
                     action={<span className="text-xs text-faint">matched by {usage[current.id] ?? 0} incident(s)</span>}>
              <Markdown>{current.markdown}</Markdown>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}
