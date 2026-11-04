"use client";
import Link from "next/link";
import { Badge, Empty, ErrorNote, PageTitle } from "@/components/ui";
import { usePolling } from "@/lib/api";

type Event = { id: number; run_id: string | null; ts: string; actor: string; type: string; data: Record<string, any>; hash: string };

function summarize(data: Record<string, any>) {
  const parts: string[] = [];
  if (data.tool) parts.push(data.tool);
  if (data.decision) parts.push(data.decision.replace("_", " "));
  if (data.reasons?.length) parts.push(data.reasons.join(", "));
  if (data.note) parts.push(`“${data.note}”`);
  if (data.error) parts.push(data.error);
  if (data.name) parts.push(data.name);
  return parts.join(" · ");
}

export default function AuditPage() {
  const { data, error } = usePolling<Event[]>("/audit?limit=300", 5000);
  const { data: chain } = usePolling<{ valid: boolean; events: number; broken_at?: number }>("/audit/verify", 15000);
  return (
    <>
      <PageTitle
        title="Audit trail"
        subtitle="Append-only and hash-chained, so changing any past event is detectable. Personal data is redacted before it's written."
        action={chain && (chain.valid
          ? <Badge tone="good" icon="✓">Chain intact · {chain.events} events</Badge>
          : <Badge tone="bad" icon="✕">Chain broken at event {chain.broken_at}</Badge>)}
      />
      <ErrorNote>{error}</ErrorNote>
      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        {data?.length ? (
          <table className="w-full text-left text-xs">
            <thead className="border-b border-line text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Time</th>
                <th className="px-3 py-2 font-medium">Event</th>
                <th className="px-3 py-2 font-medium">Actor</th>
                <th className="px-3 py-2 font-medium">Details</th>
                <th className="px-3 py-2 font-medium">Task</th>
                <th className="px-3 py-2 font-medium">Hash</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {data.map((event) => (
                <tr key={event.id} className="border-b border-line last:border-0">
                  <td className="whitespace-nowrap px-3 py-1.5 text-muted">{new Date(event.ts).toLocaleString()}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-medium">{event.type}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 text-muted">{event.actor}</td>
                  <td className="max-w-md truncate px-3 py-1.5" title={summarize(event.data)}>{summarize(event.data)}</td>
                  <td className="px-3 py-1.5">{event.run_id ? <Link className="underline-offset-2 hover:underline" href={`/runs/${event.run_id}`}>{event.run_id.slice(0, 6)}</Link> : "—"}</td>
                  <td className="px-3 py-1.5 text-muted">{event.hash.slice(0, 8)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty>{data ? "No events yet." : "Loading…"}</Empty>
        )}
      </div>
    </>
  );
}
