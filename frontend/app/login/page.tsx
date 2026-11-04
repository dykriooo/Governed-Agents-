"use client";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Button, ErrorNote, Field, inputClass } from "@/components/ui";
import { api, saveToken } from "@/lib/api";

const ACCOUNTS = [
  ["student", "Submits tasks"],
  ["approver", "Reviews risky actions"],
  ["admin", "Manages policies, authorizes high-value payments"],
  ["auditor", "Reads the audit trail"],
];

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("student");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api<{ token: string }>("/auth/login", { method: "POST", json: { username, password } });
      saveToken(result.token);
      router.push("/");
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto max-w-sm px-4 py-16">
      <h1 className="text-2xl font-semibold tracking-tight">GovernAI</h1>
      <p className="mt-1 text-sm text-muted">Autonomy with accountability.</p>
      <form onSubmit={submit} className="mt-8 space-y-4">
        <Field label="Username">
          <input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </Field>
        <Field label="Password">
          <input className={inputClass} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </Field>
        <ErrorNote>{error}</ErrorNote>
        <Button type="submit" disabled={busy} className="w-full">{busy ? "Signing in…" : "Sign in"}</Button>
      </form>
      <div className="mt-8 border-t border-line pt-4 text-sm">
        <p className="font-medium">Demo accounts</p>
        <p className="text-muted">The password is set by GOVERNAI_DEMO_PASSWORD (default “demo”).</p>
        <ul className="mt-2 space-y-1">
          {ACCOUNTS.map(([name, role]) => (
            <li key={name}>
              <button type="button" onClick={() => setUsername(name)} className="font-mono underline-offset-2 hover:underline">{name}</button>
              <span className="text-muted"> — {role}</span>
            </li>
          ))}
        </ul>
      </div>
    </main>
  );
}
