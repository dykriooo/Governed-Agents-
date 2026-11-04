"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { ApprovalCard, SCOPE_LABEL, type Approval } from "@/components/approval";
import { useUser } from "@/components/shell";
import { Badge, Button, Card, DecisionBadge, ErrorNote, Field, Json, RiskBadge, StatusBadge, inputClass } from "@/components/ui";
import { api, formatTime, titleCase, usePolling } from "@/lib/api";

type Step = { tool: string; description: string; status: string; risk?: string; expected_decision?: string; policies?: string[]; depends_on?: number[] };
type Call = { id: string; step_index: number; tool: string; args: unknown; risk: string; decision: string; reasons: { policy: string; why: string; hard?: boolean }[]; status: string; attempts: number; output: unknown; error: string | null; duration_ms: number | null; created_at: string };
type Missing = { name: string; label: string; type: string; options: string[]; reason: string };
type Run = {
  id: string; instruction: string; status: string; workflow: string | null; planner: string | null; planner_note: string | null;
  owner: string; error: string | null; created_at: string; finished_at: string | null; plan: Step[]; missing: Missing[];
  report: any; tool_calls: Call[]; approvals: Approval[]; audit: { id: number; ts: string; actor: string; type: string; data: any; hash: string }[];
};

const LIVE = new Set(["queued", "planning", "running", "awaiting_approval", "awaiting_input"]);

function MissingForm({ run, onDone }: { run: Run; onDone: () => void }) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api(`/runs/${run.id}/input`, { method: "POST", json: { values } });
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="border-warn/50">
      <h3 className="font-semibold">The agent needs a few details</h3>
      <form onSubmit={submit} className="mt-3 space-y-3">
        {run.missing.map((field) => (
          <Field key={field.name} label={field.label} hint={`— ${field.reason}`}>
            {field.options.length ? (
              <select required className={inputClass} value={values[field.name] ?? ""} onChange={(e) => setValues({ ...values, [field.name]: e.target.value })}>
                <option value="">Choose…</option>
                {field.options.map((option) => <option key={option}>{option}</option>)}
              </select>
            ) : (
              <input required type={field.type === "date" || field.type === "email" ? field.type : "text"} className={inputClass} value={values[field.name] ?? ""} onChange={(e) => setValues({ ...values, [field.name]: e.target.value })} />
            )}
          </Field>
        ))}
        <ErrorNote>{error}</ErrorNote>
        <Button type="submit" disabled={busy}>Continue</Button>
      </form>
    </Card>
  );
}

function Banner({ run }: { run: Run }) {
  if (run.status === "blocked") {
    return <ErrorNote><strong>Blocked by policy.</strong> {run.error} This can't be overridden by approval.</ErrorNote>;
  }
  if (run.status === "failed" || run.status === "rejected") return <ErrorNote>{run.error}</ErrorNote>;
  return null;
}

function StepRow({ step, index, calls, ended }: { step: Step; index: number; calls: Call[]; ended: boolean }) {
  const last = calls[calls.length - 1];
  const hasDetail = calls.length > 0;
  const decision = last?.decision ?? (step.expected_decision === "deny" ? "deny" : undefined);
  const status = step.status ?? "pending";
  const header = (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="w-5 shrink-0 text-right text-xs tabular-nums text-muted">{index + 1}</span>
      <span className="min-w-0 flex-1 text-sm">{step.description}</span>
      {(last?.risk ?? step.risk) && <RiskBadge risk={last?.risk ?? step.risk!} />}
      {decision && <DecisionBadge decision={decision} />}
      <StatusBadge status={ended && status === "pending" ? "not_executed" : status} />
    </div>
  );
  if (!hasDetail) return <li className="px-3 py-2.5">{header}</li>;
  return (
    <li>
      <details className="group">
        <summary className="cursor-pointer list-none px-3 py-2.5 hover:bg-sunken/60">{header}</summary>
        <div className="space-y-3 border-t border-line bg-sunken/40 px-3 py-3 pl-11 text-sm">
          <p className="font-mono text-xs text-muted">{step.tool}{step.depends_on?.length ? ` · depends on step ${step.depends_on.map((d) => d + 1).join(", ")}` : ""}</p>
          {calls.map((call) => (
            <div key={call.id} className="space-y-2">
              <ul className="space-y-0.5">
                {call.reasons.map((reason) => (
                  <li key={reason.policy}><span className="font-medium">{reason.policy}:</span> <span className="text-muted">{reason.why}</span></li>
                ))}
              </ul>
              {call.attempts > 1 && <Badge tone="warn" icon="↻">Took {call.attempts} attempts</Badge>}
              {call.error && <p className="text-bad">{call.error}</p>}
              <div className="grid gap-2 lg:grid-cols-2">
                <div><p className="mb-1 text-xs text-muted">Input (redacted)</p><Json value={call.args} /></div>
                {call.output != null && <div><p className="mb-1 text-xs text-muted">Output (redacted)</p><Json value={call.output} /></div>}
              </div>
            </div>
          ))}
        </div>
      </details>
    </li>
  );
}

export default function RunPage() {
  const { id } = useParams<{ id: string }>();
  const user = useUser();
  const { data: run, error, refresh } = usePolling<Run>(`/runs/${id}`, 1200, (value) => !value || LIVE.has(value.status));
  const [retryError, setRetryError] = useState<string | null>(null);

  if (error && !run) return <ErrorNote>{error}</ErrorNote>;
  if (!run) return <p className="text-sm text-muted">Loading…</p>;

  const pending = run.approvals.filter((a) => a.status === "pending");
  const decided = run.approvals.filter((a) => a.status !== "pending");
  const canRetry = run.status === "failed" && run.plan?.length > 0 && (run.owner === user.username || user.role === "admin");

  async function retry() {
    setRetryError(null);
    try {
      await api(`/runs/${id}/retry`, { method: "POST" });
      await refresh();
    } catch (e) {
      setRetryError((e as Error).message);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <Link href="/" className="text-sm text-muted underline-offset-2 hover:underline">← Tasks</Link>
        <h1 className="mt-2 text-xl font-semibold tracking-tight">{run.instruction}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted">
          <StatusBadge status={run.status} />
          {run.workflow && <span>{titleCase(run.workflow)}</span>}
          <span>Started by {run.owner}, {formatTime(run.created_at)}</span>
        </div>
      </div>

      <Banner run={run} />
      {canRetry && (
        <div className="flex items-center gap-3">
          <Button variant="secondary" onClick={retry}>Retry from last checkpoint</Button>
          <ErrorNote>{retryError}</ErrorNote>
        </div>
      )}
      {run.status === "awaiting_input" && run.owner === user.username && <MissingForm run={run} onDone={refresh} />}
      {run.status === "awaiting_input" && run.owner !== user.username && <p className="text-sm text-muted">Waiting for {run.owner} to supply missing details.</p>}
      {pending.map((approval) => <ApprovalCard key={approval.id} approval={approval} requester={run.owner} onDecided={refresh} />)}

      <section>
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-lg font-semibold">Execution plan</h2>
          {run.planner && <span className="text-xs text-muted">Planned by: {run.planner === "rules" ? "rule-based planner" : run.planner}</span>}
        </div>
        {run.planner_note && <p className="mb-2 text-xs text-muted">{run.planner_note}</p>}
        {run.plan?.length ? (
          <ol className="divide-y divide-line rounded-lg border border-line bg-surface">
            {run.plan.map((step, index) => (
              <StepRow key={index} step={step} index={index} ended={!LIVE.has(run.status)} calls={run.tool_calls.filter((c) => c.step_index === index)} />
            ))}
          </ol>
        ) : (
          <p className="text-sm text-muted">{LIVE.has(run.status) ? "Planning…" : "No plan was created."}</p>
        )}
      </section>

      {decided.length > 0 && (
        <section>
          <h2 className="mb-2 text-lg font-semibold">Decisions</h2>
          <ul className="space-y-2 text-sm">
            {decided.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2">
                <StatusBadge status={a.status} />
                {a.scope && <span className="text-xs text-muted">{SCOPE_LABEL[a.scope]}</span>}
                <span>{a.summary}</span>
                <span className="text-muted">by {a.decided_by}, {formatTime(a.decided_at)}{a.note ? ` — “${a.note}”` : ""}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {run.report && (
        <section>
          <h2 className="mb-2 text-lg font-semibold">Execution report</h2>
          <Card>
            <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
              <div><dt className="text-xs text-muted">Outcome</dt><dd className="mt-1"><StatusBadge status={run.report.status} /></dd></div>
              <div><dt className="text-xs text-muted">Duration</dt><dd className="mt-1 tabular-nums">{run.report.duration_seconds}s</dd></div>
              <div><dt className="text-xs text-muted">Policy checks</dt><dd className="mt-1 tabular-nums">{run.report.policy_decisions.allow} allowed · {run.report.policy_decisions.require_approval} need approval · {run.report.policy_decisions.deny} denied</dd></div>
              <div><dt className="text-xs text-muted">Audit events</dt><dd className="mt-1 tabular-nums">{run.report.audit_events}</dd></div>
            </dl>
            {run.report.audit_head && <p className="mt-4 break-all font-mono text-xs text-muted">Audit chain head: {run.report.audit_head}</p>}
          </Card>
        </section>
      )}

      <section>
        <details>
          <summary className="cursor-pointer text-lg font-semibold">Audit trail ({run.audit.length} events)</summary>
          <ol className="mt-2 divide-y divide-line rounded-lg border border-line bg-surface font-mono text-xs">
            {run.audit.map((event) => (
              <li key={event.id} className="flex flex-wrap gap-x-3 px-3 py-1.5">
                <span className="text-muted">{new Date(event.ts).toLocaleTimeString()}</span>
                <span className="font-medium">{event.type}</span>
                <span className="text-muted">{event.actor}</span>
                {event.data.tool && <span>{event.data.tool}</span>}
              </li>
            ))}
          </ol>
        </details>
      </section>
    </div>
  );
}
