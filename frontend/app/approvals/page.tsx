"use client";
import Link from "next/link";
import { ApprovalCard, type Approval } from "@/components/approval";
import { Empty, ErrorNote, PageTitle } from "@/components/ui";
import { usePolling } from "@/lib/api";

export default function ApprovalsPage() {
  const { data, error, refresh } = usePolling<Approval[]>("/approvals?status=pending", 2500);
  return (
    <>
      <PageTitle title="Approvals" subtitle="High-risk actions wait here. The agent continues only after a decision, and only with exactly the values shown." />
      <ErrorNote>{error}</ErrorNote>
      {data?.length ? (
        <div className="space-y-4">
          {data.map((approval) => (
            <div key={approval.id}>
              <ApprovalCard approval={approval} onDecided={refresh} />
              <Link href={`/runs/${approval.run_id}`} className="mt-1 inline-block text-sm text-muted underline-offset-2 hover:underline">View the full task</Link>
            </div>
          ))}
        </div>
      ) : (
        <Empty>{data ? "Nothing is waiting for approval." : "Loading…"}</Empty>
      )}
    </>
  );
}
