"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { adminApi } from "@/lib/admin-api";
import type { ApiError, PendingUser } from "@/types/auth";

export function usePendingUsers() {
  const [users, setUsers] = useState<PendingUser[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [processingId, setProcessingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await adminApi.getPendingUsers(0, 50);
      setUsers(data.content);
      setTotal(data.totalElements);
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't load pending approvals.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const approve = useCallback(async (userId: string) => {
    setProcessingId(userId);
    try {
      await adminApi.approveUser(userId);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
      setTotal((t) => Math.max(0, t - 1));
      toast.success("User approved — they'll receive an email notification");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't approve user.");
    } finally {
      setProcessingId(null);
    }
  }, []);

  const reject = useCallback(async (userId: string) => {
    setProcessingId(userId);
    try {
      await adminApi.rejectUser(userId);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
      setTotal((t) => Math.max(0, t - 1));
      toast.success("Request rejected");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't reject user.");
    } finally {
      setProcessingId(null);
    }
  }, []);

  return { users, total, isLoading, processingId, approve, reject, refetch: load };
}
