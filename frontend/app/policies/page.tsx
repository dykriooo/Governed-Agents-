"use client";
import { useState, type FormEvent } from "react";
import { useUser } from "@/components/shell";
import { Badge, Button, Card, ErrorNote, Field, Json, PageTitle, inputClass } from "@/components/ui";
import { api, usePolling } from "@/lib/api";

type Condition = { field: string; op: string; value?: any };
type Rule = {
  id: string; name: string; description: string; source_text: string | null; effect: string; hard: boolean; locked: boolean;
  enabled: boolean; match: { tags?: string[]; tools?: string[] }; conditions: Condition[]; required_role: string;
};

function describeCondition(c: Condition) {
  if (c.op === "domain_not_in") return "destination isn't on the approved list";
  if (c.op === "contains_pii") return "the call contains personal data";
  if (c.op === "not_actor") return "the data belongs to another user";
  if (c.op === "gt") return `${c.field.replace("args.", "")} is above ${Number(c.value).toLocaleString()}`;
  return `${c.field} ${c.op} ${c.value}`;
}

function DomainEditor({ rule, onSaved }: { rule: Rule; onSaved: () => void }) {
  const condition = rule.conditions.find((c) => c.op === "domain_not_in")!;
  const [text, setText] = useState((condition.value as string[]).join(", "));
  const [error, setError] = useState<string | null>(null);

  async function save(event: FormEvent) {
    event.preventDefault();
    setError(null);
    const value = text.split(",").map((d) => d.trim()).filter(Boolean);
    try {
      await api(`/policies/${rule.id}`, { method: "PATCH", json: { conditions: rule.conditions.map((c) => (c === condition ? { ...c, value } : c)) } });
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <form onSubmit={save} className="mt-3 space-y-2">
      <Field label="Approved websites" hint="host or host:port, comma separated">
        <div className="flex gap-2">
          <input className={`${inputClass} font-mono`} value={text} onChange={(e) => setText(e.target.value)} />
          <Button type="submit" variant="secondary">Save</Button>
        </div>
      </Field>
      <ErrorNote>{error}</ErrorNote>
    </form>
  );
}

function RuleCard({ rule, isAdmin, refresh }: { rule: Rule; isAdmin: boolean; refresh: () => void }) {
  const [error, setError] = useState<string | null>(null);

  async function run(action: () => Promise<unknown>) {
    setError(null);
    try {
      await action();
      refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <Card className={rule.enabled ? "" : "opacity-60"}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">{rule.name}</h3>
        {rule.effect === "deny" ? <Badge tone="bad" icon="⊘">{rule.hard ? "Hard deny" : "Deny"}</Badge> : <Badge tone="warn" icon="!">{rule.required_role === "admin" ? "Needs admin approval" : "Needs approval"}</Badge>}
        {rule.locked && <Badge icon="🔒">Locked</Badge>}
        {!rule.enabled && <Badge>Off</Badge>}
      </div>
      {rule.description && <p className="mt-1 text-sm text-muted">{rule.description}</p>}
      {rule.source_text && <p className="mt-1 text-sm text-muted">Written as: “{rule.source_text}”</p>}
      <p className="mt-2 text-xs text-muted">
        Applies to {rule.match.tags?.join(", ") || rule.match.tools?.join(", ") || "all"} actions
        {rule.conditions.length > 0 && <> when {rule.conditions.map(describeCondition).join(" and ")}</>}
      </p>
      {isAdmin && rule.conditions.some((c) => c.op === "domain_not_in") && <DomainEditor rule={rule} onSaved={refresh} />}
      <ErrorNote>{error}</ErrorNote>
      {isAdmin && !rule.locked && (
        <div className="mt-3 flex gap-2">
          <Button variant="secondary" onClick={() => run(() => api(`/policies/${rule.id}`, { method: "PATCH", json: { enabled: !rule.enabled } }))}>{rule.enabled ? "Turn off" : "Turn on"}</Button>
          <Button variant="danger" onClick={() => run(() => api(`/policies/${rule.id}`, { method: "DELETE" }))}>Delete</Button>
        </div>
      )}
    </Card>
  );
}

function NewPolicy({ onCreated }: { onCreated: () => void }) {
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [draft, setDraft] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  async function compile(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setDraft(null);
    try {
      const result = await api<{ rule: any }>("/policies/compile", { method: "POST", json: { text } });
      setDraft(result.rule);
      setName(text.slice(0, 80));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function create() {
    setError(null);
    try {
      await api("/policies", { method: "POST", json: { ...draft, name, source_text: text, description: text } });
      setDraft(null);
      setText("");
      onCreated();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <Card className="mb-6">
      <form onSubmit={compile} className="space-y-3">
        <Field label="Add a policy in plain language">
          <input className={inputClass} value={text} onChange={(e) => setText(e.target.value)} minLength={3} required placeholder="Do not make payments above ₹2,000" />
        </Field>
        <Button type="submit" variant="secondary">Translate to a rule</Button>
      </form>
      <div className="mt-3"><ErrorNote>{error}</ErrorNote></div>
      {draft && (
        <div className="mt-4 space-y-3">
          <p className="text-sm">Check that this rule says what you meant. It applies to the very next tool call once saved.</p>
          <Json value={draft} />
          <Field label="Name"><input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Button onClick={create} disabled={name.length < 3}>Save policy</Button>
        </div>
      )}
    </Card>
  );
}

export default function PoliciesPage() {
  const user = useUser();
  const isAdmin = user.role === "admin";
  const { data, error, refresh } = usePolling<Rule[]>("/policies", 15000);
  return (
    <>
      <PageTitle title="Policies" subtitle="Every tool call is checked against these rules before it runs. Rules can only add restrictions, and high-risk actions always need approval, whatever is configured here." />
      {isAdmin && <NewPolicy onCreated={refresh} />}
      <ErrorNote>{error}</ErrorNote>
      <div className="space-y-3">
        {data?.map((rule) => <RuleCard key={rule.id} rule={rule} isAdmin={isAdmin} refresh={refresh} />)}
      </div>
    </>
  );
}
