"use client";
import { useState } from "react";
import { useUser } from "@/components/shell";
import { Badge, Button, Card, Empty, ErrorNote, PageTitle } from "@/components/ui";
import { api, formatTime, usePolling } from "@/lib/api";

type Metric = { name: string; value: number | null; target: string; unit: string; met: boolean | null; detail: string };
type Scenario = { id: string; title: string; passed: boolean; seconds: number; error: string | null; checks: { check: string; passed: boolean }[] };
type Report = { id: string; status: string; triggered_by: string; results: Scenario[]; metrics: Metric[]; error: string | null; created_at: string; finished_at: string | null };
type Live = {
  runs: number; by_status: Record<string, number>; completion_rate: number | null; average_duration_seconds: number | null;
  pending_approvals: number; tool_calls: number; executed: number; denied: number; failed: number; retried: number;
  unauthorized_executions: number; irreversible_without_review: number; high_risk_executed: number; high_risk_with_approval: number; fully_logged: number;
  audit_chain: { valid: boolean; events: number };
};

function Stat({ label, value, note }: { label: string; value: string | number; note?: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-1 text-2xl font-semibold tabular-nums tracking-tight">{value}</dd>
      {note && <p className="mt-0.5 text-xs text-muted">{note}</p>}
    </div>
  );
}

function MetricsTable({ metrics }: { metrics: Metric[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs text-muted">
          <tr>
            <th className="py-2 pr-4 font-medium">Metric</th>
            <th className="py-2 pr-4 text-right font-medium">Measured</th>
            <th className="py-2 pr-4 font-medium">Target</th>
            <th className="py-2 pr-4 font-medium">Result</th>
            <th className="py-2 font-medium">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {metrics.map((metric) => (
            <tr key={metric.name} className="border-b border-line last:border-0">
              <td className="py-2 pr-4">{metric.name}</td>
              <td className="py-2 pr-4 text-right tabular-nums">{metric.value === null ? "n/a" : `${metric.value}${metric.unit}`}</td>
              <td className="whitespace-nowrap py-2 pr-4 text-muted">{metric.target}</td>
              <td className="py-2 pr-4">
                {metric.met === null ? <Badge>Informational</Badge> : metric.met ? <Badge tone="good" icon="✓">Met</Badge> : <Badge tone="bad" icon="✕">Missed</Badge>}
              </td>
              <td className="py-2 text-xs text-muted">{metric.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScenarioList({ scenarios }: { scenarios: Scenario[] }) {
  return (
    <ul className="divide-y divide-line">
      {scenarios.map((scenario) => (
        <li key={scenario.id}>
          <details>
            <summary className="flex cursor-pointer list-none flex-wrap items-center gap-3 py-2 text-sm">
              {scenario.passed ? <Badge tone="good" icon="✓">Passed</Badge> : <Badge tone="bad" icon="✕">Failed</Badge>}
              <span className="min-w-0 flex-1">{scenario.title}</span>
              <span className="text-xs tabular-nums text-muted">{scenario.seconds}s</span>
            </summary>
            <ul className="space-y-1 pb-3 pl-2 text-sm">
              {scenario.checks.map((check) => (
                <li key={check.check} className={check.passed ? "text-muted" : "text-bad"}>
                  <span aria-hidden>{check.passed ? "✓ " : "✕ "}</span>
                  <span className="sr-only">{check.passed ? "Passed: " : "Failed: "}</span>{check.check}
                </li>
              ))}
              {scenario.error && <li className="whitespace-pre-wrap font-mono text-xs text-bad">{scenario.error}</li>}
            </ul>
          </details>
        </li>
      ))}
    </ul>
  );
}

export default function DashboardPage() {
  const user = useUser();
  const { data: live, error: liveError } = usePolling<Live>("/metrics", 4000);
  const { data: reports, refresh } = usePolling<Report[]>("/evaluations", 2000, (value) => !value || value.some((r) => r.status === "running"));
  const [error, setError] = useState<string | null>(null);
  const latest = reports?.[0];
  const running = latest?.status === "running";

  async function start() {
    setError(null);
    try {
      await api("/evaluations", { method: "POST" });
      location.reload();
    } catch (e) {
      setError((e as Error).message);
      refresh();
    }
  }

  return (
    <>
      <PageTitle title="Evaluation" subtitle="How the agent is performing, and whether governance is holding, measured from execution records." />
      <ErrorNote>{liveError}</ErrorNote>

      {live && (
        <section className="mb-8" aria-label="Live activity">
          <h2 className="mb-3 text-lg font-semibold">Live activity</h2>
          <dl className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Tasks" value={live.runs} note={`${live.by_status.completed ?? 0} completed, ${live.by_status.failed ?? 0} failed`} />
            <Stat label="Completion rate" value={live.completion_rate === null ? "—" : `${live.completion_rate}%`} note="Excludes tasks stopped by policy or an approver" />
            <Stat label="Stopped by governance" value={(live.by_status.blocked ?? 0) + (live.by_status.rejected ?? 0)} note={`${live.by_status.blocked ?? 0} blocked, ${live.by_status.rejected ?? 0} rejected`} />
            <Stat label="Unauthorized executions" value={live.unauthorized_executions} note="Target: 0" />
            <Stat label="High-risk calls authorized" value={`${live.high_risk_with_approval}/${live.high_risk_executed}`} note="By approval, task grant or allow rule. Target: all" />
            <Stat label="Irreversible, not individually reviewed" value={live.irreversible_without_review} note="Ran under a task or standing grant" />
            <Stat label="Failed tool calls" value={live.failed} note={`${live.retried} needed a retry`} />
            <Stat label="Average task time" value={live.average_duration_seconds === null ? "—" : `${live.average_duration_seconds}s`} note="Includes time waiting for people" />
            <Stat label="Audit log" value={live.audit_chain.valid ? "Intact" : "BROKEN"} note={`${live.audit_chain.events} chained events`} />
          </dl>
        </section>
      )}

      <section>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold">Evaluation report</h2>
            <p className="text-sm text-muted">Scenarios run the real engine, browser and portal. Results are checked against the portal's own records and a canary server.</p>
          </div>
          {user.role === "admin" && <Button onClick={start} disabled={running}>{running ? "Running…" : "Run evaluation"}</Button>}
        </div>
        <ErrorNote>{error}</ErrorNote>
        {!latest && <Card><Empty>{reports ? (user.role === "admin" ? "No evaluation has been run yet." : "No evaluation has been run yet. An administrator can start one.") : "Loading…"}</Empty></Card>}
        {running && <Card><Empty>Running the scenarios. This takes about a minute.</Empty></Card>}
        {latest && latest.status === "error" && <ErrorNote>{latest.error}</ErrorNote>}
        {latest && latest.status === "finished" && (
          <div className="space-y-4">
            <Card>
              <p className="mb-3 text-xs text-muted">
                Run by {latest.triggered_by}, {formatTime(latest.finished_at)}. {latest.results.filter((r) => r.passed).length} of {latest.results.length} scenarios passed. Targets are from PRD section 9; results describe this test suite on a mock portal, not production performance.
              </p>
              <MetricsTable metrics={latest.metrics} />
            </Card>
            <Card>
              <h3 className="mb-1 font-semibold">Scenarios</h3>
              <ScenarioList scenarios={latest.results} />
            </Card>
          </div>
        )}
      </section>
    </>
  );
}
