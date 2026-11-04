"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, saveToken, type Role, type User } from "@/lib/api";

const UserContext = createContext<User | null>(null);

export function useUser(): User {
  const user = useContext(UserContext);
  if (!user) throw new Error("useUser needs a signed-in shell");
  return user;
}

const OVERSIGHT: Role[] = ["approver", "admin", "auditor"];
const NAV: { href: string; label: string; roles?: Role[] }[] = [
  { href: "/", label: "Tasks" },
  { href: "/approvals", label: "Approvals", roles: OVERSIGHT },
  { href: "/policies", label: "Policies" },
  { href: "/dashboard", label: "Evaluation", roles: OVERSIGHT },
  { href: "/audit", label: "Audit", roles: ["admin", "auditor"] },
];

const ROLE_LABEL: Record<Role, string> = { end_user: "End user", approver: "Approver", admin: "Administrator", auditor: "Auditor" };

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const isLogin = pathname === "/login";

  useEffect(() => {
    if (isLogin) {
      setUser(null);
      return;
    }
    api<User>("/me").then(setUser).catch((e) => setFailure(e.message));
  }, [isLogin, pathname]);

  if (isLogin) return <>{children}</>;
  if (failure && !user) {
    return <main className="mx-auto max-w-md p-8 text-center text-sm text-muted">{failure} Check that the backend is running on port 8000, then reload.</main>;
  }
  if (!user) return <main className="p-8 text-center text-sm text-muted">Loading…</main>;

  const signOut = () => {
    saveToken(null);
    router.push("/login");
  };

  return (
    <UserContext.Provider value={user}>
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <Link href="/" className="font-semibold tracking-tight">GovernAI</Link>
          <nav aria-label="Main" className="flex flex-1 flex-wrap gap-1">
            {NAV.filter((item) => !item.roles || item.roles.includes(user.role)).map((item) => {
              const current = item.href === "/" ? pathname === "/" || pathname.startsWith("/runs") : pathname.startsWith(item.href);
              return (
                <Link key={item.href} href={item.href} aria-current={current ? "page" : undefined}
                  className={`rounded-md px-2.5 py-1.5 text-sm ${current ? "bg-sunken font-medium" : "text-muted hover:text-ink"}`}>
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-muted">{user.username} · {ROLE_LABEL[user.role]}</span>
            <button onClick={signOut} className="rounded px-1 underline-offset-2 hover:underline">Sign out</button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
    </UserContext.Provider>
  );
}
