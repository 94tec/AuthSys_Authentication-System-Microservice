// ─────────────────────────────────────────────────────────────────
// Maps to: AdminController, AdminAuthController,
//          AdminRolePermissionController, AuditLogController
// Roles with admin access: SUPER_ADMIN(27 perms), ADMIN(27 perms)
// ─────────────────────────────────────────────────────────────────
import { apiClient } from "@/lib/api-client";
import type {
  AuditLog,
  Page,
  PendingUser,
  Role,
  RolePermissions,
  User,
  UserPermissions,
} from "@/types/auth";

export const adminApi = {
  // ── AdminController: user management ────────────────────────
  getAllUsers: async (page = 0, size = 20, status?: string): Promise<Page<User>> =>
    (await apiClient.get<Page<User>>("/admin/users", { params: { page, size, status } }))
      .data,

  getUserById: async (userId: string): Promise<User> =>
    (await apiClient.get<User>(`/admin/users/${userId}`)).data,

  // ── AdminController: pending approvals ──────────────────────
  getPendingUsers: async (page = 0, size = 20): Promise<Page<PendingUser>> =>
    (
      await apiClient.get<Page<PendingUser>>("/admin/users/pending", {
        params: { page, size },
      })
    ).data,

  approveUser: async (userId: string): Promise<User> =>
    (await apiClient.post<User>(`/admin/users/${userId}/approve`)).data,

  rejectUser: async (userId: string, reason?: string): Promise<User> =>
    (await apiClient.post<User>(`/admin/users/${userId}/reject`, { reason })).data,

  lockUser: async (userId: string): Promise<User> =>
    (await apiClient.post<User>(`/admin/users/${userId}/lock`)).data,

  unlockUser: async (userId: string): Promise<User> =>
    (await apiClient.post<User>(`/admin/users/${userId}/unlock`)).data,

  updateUserRoles: async (userId: string, roles: Role[]): Promise<User> =>
    (await apiClient.patch<User>(`/admin/users/${userId}/roles`, { roles })).data,

  forcePasswordReset: async (userId: string): Promise<{ message: string }> =>
    (
      await apiClient.post<{ message: string }>(
        `/admin/users/${userId}/force-password-reset`
      )
    ).data,

  // ── AdminRolePermissionController ───────────────────────────
  getAllRolePermissions: async (): Promise<RolePermissions[]> =>
    (await apiClient.get<RolePermissions[]>("/admin/roles/permissions")).data,

  getRolePermissions: async (role: Role): Promise<RolePermissions> =>
    (await apiClient.get<RolePermissions>(`/admin/roles/${role}/permissions`)).data,

  getUserPermissions: async (userId: string): Promise<UserPermissions> =>
    (await apiClient.get<UserPermissions>(`/admin/users/${userId}/permissions`)).data,

  updateRolePermissions: async (
    role: Role,
    permissions: string[]
  ): Promise<RolePermissions> =>
    (
      await apiClient.put<RolePermissions>(`/admin/roles/${role}/permissions`, {
        permissions,
      })
    ).data,

  // ── AuditLogController ───────────────────────────────────────
  getAuditLogs: async (
    page = 0,
    size = 30,
    filters?: {
      userId?: string;
      action?: string;
      from?: string;
      to?: string;
    }
  ): Promise<Page<AuditLog>> =>
    (
      await apiClient.get<Page<AuditLog>>("/admin/audit-logs", {
        params: { page, size, ...filters },
      })
    ).data,

  getAuditLogsByUser: async (
    userId: string,
    page = 0,
    size = 20
  ): Promise<Page<AuditLog>> =>
    (
      await apiClient.get<Page<AuditLog>>(`/admin/audit-logs/user/${userId}`, {
        params: { page, size },
      })
    ).data,

  // ── BootstrapDiagnosticController ───────────────────────────
  getBootstrapStatus: async (): Promise<Record<string, unknown>> =>
    (await apiClient.get<Record<string, unknown>>("/admin/bootstrap/status")).data,
};
