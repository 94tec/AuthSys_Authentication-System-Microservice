package com.techStack.authSys.models.user;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Enhanced Permission Data
 *
 * Comprehensive permission information for a user including:
 * - Basic permission data (roles, permissions, status)
 * - Approval tracking (who, when)
 * - Role hierarchy information
 * - Permission metadata
 * - Audit trail
 * - Versioning
 *
 * @author TechStack Security Team
 * @version 2.0 - Enhanced
 */
@Data
@Builder
public class PermissionData {

    /* =========================
       Core Fields
       ========================= */

    /**
     * User ID this permission data belongs to
     */
    private String userId;

    /**
     * User email for reference
     */
    private String email;

    /**
     * List of role names assigned to user
     */
    private List<String> roles;

    /**
     * List of permission strings granted to user
     */
    private List<String> permissions;

    /**
     * Current user status
     */
    private UserStatus status;

    /**
     * Whether permissions are currently active
     */
    @Builder.Default
    private boolean active = true;

    /**
     * Permission data version (for optimistic locking)
     */
    @Builder.Default
    private int version = 1;

    /* =========================
       Approval Tracking
       ========================= */

    /**
     * ID of approver who granted these permissions
     */
    private String approvedBy;

    /**
     * When approval was granted
     */
    private Instant approvedAt;

    /**
     * When permissions were granted/activated
     */
    private Instant grantedAt;

    /* =========================
       Hierarchy & Metadata
       ========================= */

    /**
     * Role hierarchy map (role -> inherited roles)
     * Example: {"ADMIN" -> ["MANAGER", "USER"]}
     */
    private Map<String, List<String>> roleHierarchy;

    /**
     * Permission metadata (source, resolution info, etc.)
     */
    private Map<String, Object> permissionMetadata;

    /* =========================
       Audit Trail
       ========================= */

    /**
     * Audit trail of permission changes
     * Each entry: {"action", "performedBy", "timestamp", ...}
     */
    private List<Map<String, String>> auditTrail;

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Check if permissions are active and valid
     */
    public boolean isValid() {
        return active &&
                status == UserStatus.ACTIVE &&
                permissions != null &&
                !permissions.isEmpty();
    }

    /**
     * Get total permission count
     */
    public int getPermissionCount() {
        return permissions != null ? permissions.size() : 0;
    }

    /**
     * Get total role count
     */
    public int getRoleCount() {
        return roles != null ? roles.size() : 0;
    }

    /**
     * Check if user has specific permission
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    /**
     * Check if user has specific role
     */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    /* =========================
       Static Factory Methods
       ========================= */

    /**
     * Create empty permission data for pending users
     */
    public static PermissionData empty(String userId, String email, List<String> roles) {
        return PermissionData.builder()
                .userId(userId)
                .email(email)
                .roles(roles)
                .permissions(List.of())
                .status(UserStatus.PENDING_APPROVAL)
                .active(false)
                .version(1)
                .build();
    }

    /**
     * Create active permission data for approved users
     */
    public static PermissionData active(
            String userId,
            String email,
            List<String> roles,
            List<String> permissions,
            String approvedBy,
            Instant approvedAt) {

        return PermissionData.builder()
                .userId(userId)
                .email(email)
                .roles(roles)
                .permissions(permissions)
                .status(UserStatus.ACTIVE)
                .active(true)
                .approvedBy(approvedBy)
                .approvedAt(approvedAt)
                .grantedAt(approvedAt)
                .version(1)
                .build();
    }
}