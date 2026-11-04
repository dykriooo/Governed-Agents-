"use client";
import { useCallback, useEffect, useRef, useState } from "react";

export type Role = "end_user" | "approver" | "admin" | "auditor";
export type User = { id: string; username: string; role: Role };

const TOKEN_KEY = "governai.token";

function readToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function saveToken(token: string | null) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* private window: the session simply won't persist */
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T = any>(path: string, options: RequestInit & { json?: unknown } = {}): Promise<T> {
  const { json, ...init } = options;
  const headers = new Headers(init.headers);
  const token = readToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (json !== undefined) {
    headers.set("Content-Type", "application/json");
    init.body = JSON.stringify(json);
  }
  let response: Response;
  try {
    response = await fetch(`/api${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Can't reach the GovernAI server.");
  }
  if (response.status === 401 && path !== "/auth/login") {
    saveToken(null);
    window.location.href = "/login";
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail = typeof body?.detail === "string" ? body.detail : response.status >= 500 ? "The GovernAI server isn't responding." : `Request failed (${response.status})`;
    throw new ApiError(response.status, detail);
  }
  return response.status === 204 ? (undefined as T) : response.json();
}

/** Fetch a resource, refreshing on an interval while `active` says it may change. */
export function usePolling<T>(path: string | null, intervalMs: number, active: (data: T | null) => boolean = () => true) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const activeRef = useRef(active);
  activeRef.current = active;

  const refresh = useCallback(async () => {
    if (!path) return;
    try {
      const value = await api<T>(path);
      setData(value);
      setError(null);
      return value;
    } catch (e) {
      setError((e as Error).message);
    }
  }, [path]);

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      const value = await refresh();
      if (!stopped && activeRef.current(value ?? null)) timer = setTimeout(tick, intervalMs);
    };
    tick();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [refresh, intervalMs]);

  return { data, error, refresh };
}

export function formatTime(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function titleCase(value: string) {
  return value
    .replace(/[_.]/g, " ")
    .replace(/^\w/, (c) => c.toUpperCase())
    .replace(/\bgpa\b/i, "GPA")
    .replace(/\bid\b/i, "ID");
}
