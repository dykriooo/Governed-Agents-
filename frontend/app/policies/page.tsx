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
  if (c.op === "domain_in") return `destination is ${(c.value as string[]).join(" or ")}`;
  if (c.op === "eq") return `${c.field.replace("args.", "")} is ${c.value}`;
  if (c.op === "lte") return `${c.field.replace("args.", "")} is at most ${Number(c.value).toLocaleString()}`;
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
        {rule.effect === "deny" && <Badge tone="bad" icon="⊘">{rule.hard ? "Hard deny" : "Deny"}</Badge>}
        {rule.effect === "require_approval" && <Badge tone="warn" icon="!">{rule.required_role === "admin" ? "Ask an admin" : "Ask"}</Badge>}
        {rule.effect === "allow" && <Badge tone="good" icon="✓">Allow</Badge>}
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

type ToolInfo = { name: string; description: string; tags: string[] };
const IRREVERSIBLE = ["submission", "payment"];
const CONDITIONS: Record<string, { label: string; effects: string[]; input?: string }> = {
  always: { label: "Every call", effects: ["deny", "require_approval", "allow"] },
  host_is: { label: "Destination is", effects: ["deny", "require_approval", "allow"], input: "host or host:port, comma separated" },
  amount_above: { label: "Amount is above", effects: ["deny", "require_approval"], input: "amount in ₹" },
  amount_at_most: { label: "Amount is at most", effects: ["allow"], input: "amount in ₹" },
  pii: { label: "Contains personal data", effects: ["deny", "require_approval"] },
};

function buildConditions(kind: string, value: string): Condition[] {
  if (kind === "host_is") return [{ field: "args.url", op: "domain_in", value: value.split(",").map((d) => d.trim()).filter(Boolean) }];
  if (kind === "amount_above") return [{ field: "args.amount", op: "gt", value: Number(value) }];
  if (kind === "amount_at_most") return [{ field: "args.amount", op: "lte", value: Number(value) }];
  if (kind === "pii") return [{ field: "args", op: "contains_pii" }];
  return [];
}

function RuleBuilder({ onCreated }: { onCreated: () => void }) {
  const { data: tools } = usePolling<ToolInfo[]>("/tools", 600000);
  const [effect, setEffect] = useState("require_approval");
  const [tool, setTool] = useState("");
  const [kind, setKind] = useState("always");
  const [value, setValue] = useState("");
  const [role, setRole] = useState("approver");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const available = (tools ?? []).filter((t) => effect !== "allow" || !t.tags.some((tag) => IRREVERSIBLE.includes(tag)));
  const kinds = Object.entries(CONDITIONS).filter(([, c]) => c.effects.includes(effect));
  const needsValue = CONDITIONS[kind]?.input;

  function chooseEffect(next: string) {
    setEffect(next);
    if (!CONDITIONS[kind].effects.includes(next)) setKind("always");
    if (next === "allow" && available.every((t) => t.name !== tool)) setTool("");
    if (next === "allow" && tools?.find((t) => t.name === tool)?.tags.some((tag) => IRREVERSIBLE.includes(tag))) setTool("");
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await api("/policies", {
        method: "POST",
        json: {
          name, effect, description: name, required_role: role, hard: effect === "deny",
          match: { tools: [tool] }, conditions: buildConditions(kind, value),
        },
      });
      setName("");
      setValue("");
      setKind("always");
      onCreated();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="When the agent uses">
          <select required className={inputClass} value={tool} onChange={(e) => setTool(e.target.value)}>
            <option value="">Choose a tool…</option>
            {available.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
          </select>
        </Field>
        <Field label="And">
          <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value)}>
            {kinds.map(([key, c]) => <option key={key} value={key}>{c.label}</option>)}
          </select>
        </Field>
        <Field label="Then">
          <select className={inputClass} value={effect} onChange={(e) => chooseEffect(e.target.value)}>
            <option value="require_approval">Ask for approval</option>
            <option value="deny">Deny</option>
            <option value="allow">Allow without asking</option>
          </select>
        </Field>
      </div>
      {needsValue && (
        <Field label={CONDITIONS[kind].label} hint={needsValue}>
          <input required className={inputClass} value={value} type={kind.startsWith("amount") ? "number" : "text"} min={0} onChange={(e) => setValue(e.target.value)} />
        </Field>
      )}
      {effect === "require_approval" && (
        <Field label="Who can approve">
          <select className={inputClass} value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="approver">Approver or administrator</option>
            <option value="admin">Administrator only</option>
          </select>
        </Field>
      )}
      <Field label="Rule name">
        <input required minLength={3} maxLength={120} className={inputClass} value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <p className="text-xs text-muted">
        {effect === "allow"
          ? "Deny and ask rules still win over this. To allow submissions or payments, choose Always allow while reviewing one."
          : effect === "deny"
            ? "A deny can't be overridden by approval, and it wins over every other rule."
            : "An ask rule wins over allow rules. Only a deny outranks it."}
      </p>
      <ErrorNote>{error}</ErrorNote>
      <Button type="submit">Add rule</Button>
    </form>
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
      <h2 className="mb-3 font-semibold">Add a custom rule</h2>
      <RuleBuilder onCreated={onCreated} />
      <div className="my-5 border-t border-line" />
      <form onSubmit={compile} className="space-y-3">
        <Field label="Or describe it in plain language">
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
      <PageTitle title="Policies" subtitle="Every tool call is checked against these rules before it runs. Deny beats ask, and ask beats allow. Choosing Always allow during a review adds a rule here that waives the rules it was flagged by." />
      {isAdmin && <NewPolicy onCreated={refresh} />}
      <ErrorNote>{error}</ErrorNote>
      <div className="space-y-3">
        {data?.map((rule) => <RuleCard key={rule.id} rule={rule} isAdmin={isAdmin} refresh={refresh} />)}
      </div>
    </>
  );
}
