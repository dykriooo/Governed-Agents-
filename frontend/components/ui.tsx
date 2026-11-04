"use client";
import type { ButtonHTMLAttributes, ReactNode } from "react";

export function Button({ variant = "primary", className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  const styles = {
    primary: "bg-accent text-accent-ink hover:opacity-90",
    secondary: "border border-line bg-surface hover:bg-sunken",
    danger: "border border-bad/40 bg-surface text-bad hover:bg-bad/10",
  }[variant];
  return <button {...props} className={`min-h-9 rounded-md px-3.5 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${styles} ${className}`} />;
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`rounded-lg border border-line bg-surface p-5 ${className}`}>{children}</section>;
}

export function PageTitle({ title, subtitle, action }: { title: string; subtitle?: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 max-w-2xl text-sm text-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="font-medium">{label}</span>
      {hint && <span className="ml-1.5 text-muted">{hint}</span>}
      <div className="mt-1">{children}</div>
    </label>
  );
}

export const inputClass = "w-full rounded-md border border-line bg-surface px-3 py-2 text-sm placeholder:text-muted";

export function ErrorNote({ children }: { children: ReactNode }) {
  if (!children) return null;
  return <p role="alert" className="rounded-md border border-bad/30 bg-bad/10 px-3 py-2 text-sm text-bad">{children}</p>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-8 text-center text-sm text-muted">{children}</p>;
}

type Tone = "good" | "warn" | "bad" | "neutral" | "accent";
const TONE: Record<Tone, string> = {
  good: "text-good border-good/30 bg-good/10",
  warn: "text-warn border-warn/30 bg-warn/10",
  bad: "text-bad border-bad/30 bg-bad/10",
  neutral: "text-muted border-line bg-sunken",
  accent: "text-accent border-accent/30 bg-accent/10",
};

export function Badge({ tone = "neutral", icon, children }: { tone?: Tone; icon?: string; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 text-xs font-medium ${TONE[tone]}`}>
      {icon && <span aria-hidden>{icon}</span>}
      {children}
    </span>
  );
}

const STATUS: Record<string, [Tone, string, string]> = {
  queued: ["neutral", "○", "Queued"],
  planning: ["accent", "◐", "Planning"],
  running: ["accent", "◐", "Running"],
  pending: ["neutral", "○", "Pending"],
  awaiting_input: ["warn", "!", "Needs information"],
  awaiting_approval: ["warn", "!", "Awaiting approval"],
  completed: ["good", "✓", "Completed"],
  succeeded: ["good", "✓", "Done"],
  failed: ["bad", "✕", "Failed"],
  blocked: ["bad", "⊘", "Blocked by policy"],
  rejected: ["bad", "✕", "Rejected"],
  approved: ["good", "✓", "Approved"],
  needs_input: ["warn", "!", "Needs information"],
  not_executed: ["neutral", "○", "Not executed"],
  interrupted: ["warn", "!", "Interrupted"],
};

export function StatusBadge({ status }: { status: string }) {
  const [tone, icon, label] = STATUS[status] ?? (["neutral", "○", status] as [Tone, string, string]);
  return <Badge tone={tone} icon={icon}>{label}</Badge>;
}

export function RiskBadge({ risk }: { risk: string }) {
  const tone: Tone = risk === "high" ? "bad" : risk === "medium" ? "warn" : "neutral";
  return <Badge tone={tone}>{risk ? `${risk[0].toUpperCase()}${risk.slice(1)} risk` : "Risk unknown"}</Badge>;
}

export function DecisionBadge({ decision }: { decision: string }) {
  if (decision === "deny") return <Badge tone="bad" icon="⊘">Denied</Badge>;
  if (decision === "require_approval") return <Badge tone="warn" icon="!">Needs approval</Badge>;
  return <Badge tone="good" icon="✓">Allowed</Badge>;
}

export function Json({ value }: { value: unknown }) {
  return <pre className="overflow-x-auto rounded-md bg-sunken p-3 font-mono text-xs leading-relaxed">{JSON.stringify(value, null, 2)}</pre>;
}
