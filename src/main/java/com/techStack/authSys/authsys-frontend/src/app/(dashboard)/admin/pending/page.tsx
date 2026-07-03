"use client";

import { useCallback, useEffect, useState } from "react";
import { ShieldCheck, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/layout/page-header";
import { PendingUserCard } from "@/components/admin/pending-user-card";
import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { adminApi } from "@/lib/admin-api";
import type { PendingUser, ApiError } from "@/types/auth";

export default function PendingApprovalsPage() {
  const [users, setUsers] = useState<PendingUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [processingId, setProcessingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await adminApi.getPendingUsers();
      setUsers(data.content);
    } catch (err) {
      const e = err as ApiError;
      toast.error(e.message || "Couldn't load pending approvals.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleApprove(userId: string) {
    setProcessingId(userId);
    try {
      await adminApi.approveUser(userId);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
      toast.success("User approved and notified by email");
    } catch (err) {
      const e = err as ApiError;
      toast.error(e.message || "Couldn't approve user.");
    } finally {
      setProcessingId(null);
    }
  }

  async function handleReject(userId: string) {
    setProcessingId(userId);
    try {
      await adminApi.rejectUser(userId);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
      toast.success("Request rejected");
    } catch (err) {
      const e = err as ApiError;
      toast.error(e.message || "Couldn't reject user.");
    } finally {
      setProcessingId(null);
    }
  }

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Admin"
        title="Pending approvals"
        subtitle={`${users.length} request${users.length !== 1 ? "s" : ""} awaiting review`}
        action={
          <Button variant="outline" size="sm" onClick={load} disabled={isLoading}>
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-28 w-full rounded-xl" />
          ))}
        </div>
      ) : users.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="All clear"
          description="No pending access requests right now. New registrations will appear here for your review."
        />
      ) : (
        <div className="space-y-3">
          {users.map((user) => (
            <PendingUserCard
              key={user.id}
              user={user}
              isProcessing={processingId === user.id}
              onApprove={handleApprove}
              onReject={handleReject}
            />
          ))}
        </div>
      )}
    </div>
  );
}
