"use client";
import { useState } from "react";
import { useUser } from "@/components/shell";
import { Badge, Button, Card, ErrorNote, Field, RiskBadge, inputClass } from "@/components/ui";
import { api, titleCase } from "@/lib/api";

export type Approval = {
  id: string; run_id: string; tool: string; summary: string; consequences: string; risk: string;
  reasons: { policy: string; why: string }[]; required_role: string; status: string;
  decided_by: string | null; decided_at: string | null; note: string | null;
  review: Record<string, any> | null; requested_by?: string | null; instruction?: string | null;
};

function ReviewValues({ review }: { review: Record<string, any> }) {
  const { url, fields, ...rest } = review;
  const rows = Object.entries({ ...(fields ?? {}), ...rest }).filter(([, value]) => value !== null && typeof value !== "object");
  return (
    <dl className="grid gap-x-6 gap-y-2 rounded-md bg-sunken p-4 text-sm sm:grid-cols-2">
      {rows.map(([key, value]) => (
        <div key={key} className="min-w-0">
          <dt className="text-xs text-muted">{titleCase(key)}</dt>
          <dd className="break-words">{String(value)}</dd>
        </div>
      ))}
      {url && <div className="min-w-0 sm:col-span-2"><dt className="text-xs text-muted">Destination</dt><dd className="break-all font-mono text-xs">{url}</dd></div>}
    </dl>
  );
}

export function ApprovalCard({ approval, onDecided, requester }: { approval: Approval; onDecided: () => void; requester?: string | null }) {
  const user = useUser();
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isOwner = (requester ?? approval.requested_by) === user.username;
  const rank: Record<string, number> = { approver: 1, admin: 2 };
  const enoughAuthority = (rank[user.role] ?? 0) >= (rank[approval.required_role] ?? 2);
  const canDecide = enoughAuthority && !isOwner;

  async function decide(approve: boolean) {
    setBusy(true);
    setError(null);
    try {
      await api(`/approvals/${approval.id}/decision`, { method: "POST", json: { approve, note: note || null } });
      onDecided();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="border-warn/50">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">{approval.summary}</h3>
        <RiskBadge risk={approval.risk} />
        {approval.required_role === "admin" && <Badge tone="warn" icon="!">Needs an administrator</Badge>}
      </div>
      {approval.instruction && <p className="mt-1 text-sm text-muted">Requested by {approval.requested_by}: “{approval.instruction}”</p>}
      <p className="mt-3 text-sm"><span className="font-medium">If approved: </span>{approval.consequences}</p>
      <ul className="mt-2 space-y-0.5 text-sm text-muted">
        {approval.reasons.map((reason) => <li key={reason.policy}>Why this needs review: {reason.why}</li>)}
      </ul>
      {approval.review && <div className="mt-4"><ReviewValues review={approval.review} /></div>}
      {canDecide ? (
        <div className="mt-4 space-y-3">
          <Field label="Note" hint="optional, saved in the audit trail">
            <input className={inputClass} value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
          </Field>
          <ErrorNote>{error}</ErrorNote>
          <div className="flex flex-wrap gap-2">
            <Button disabled={busy} onClick={() => decide(true)}>Approve and continue</Button>
            <Button disabled={busy} variant="danger" onClick={() => decide(false)}>Reject</Button>
          </div>
        </div>
      ) : (
        <p className="mt-4 text-sm text-muted">
          {isOwner
            ? "Someone other than you needs to review this. Sign in as the approver to decide."
            : `This needs a decision from the ${approval.required_role} role.`}
        </p>
      )}
    </Card>
  );
}
