import apiClient from "./client"
import type { PendingUser, ApprovalAction, PaginatedResponse } from "@/types"

export const adminApi = {
  getPendingUsers: (page = 1, pageSize = 20) =>
    apiClient
      .get<PaginatedResponse<PendingUser>>("/admin/users/pending", { params: { page, pageSize } })
      .then((r) => r.data),

  approveUser: (userId: string, reason?: string) =>
    apiClient
      .post<{ message: string }>(`/admin/users/${userId}/approve`, { reason })
      .then((r) => r.data),

  rejectUser: (userId: string, reason: string) =>
    apiClient
      .post<{ message: string }>(`/admin/users/${userId}/reject`, { reason })
      .then((r) => r.data),

  lockUser: (userId: string, reason: string) =>
    apiClient
      .post<{ message: string }>(`/admin/users/${userId}/lock`, { reason })
      .then((r) => r.data),
}
