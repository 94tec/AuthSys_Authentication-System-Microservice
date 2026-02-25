package com.techStack.authSys.models.user;

import com.techStack.authSys.models.audit.AuditEntry;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Permission Data
 *
 * Comprehensive snapshot of a user's permission state, used as the read
 * model when returning permission info to callers (admin APIs, audit views).
 *
 * This is NOT a Firestore document — it is an assembled view built from:
 *   - FirestoreUserPermissions  (roles, grants, denials)
 *   - FirestoreRolePermissionsRepository (resolved role permissions)
 *   - Approval workflow state on the User entity
 *
 * Mutable list fields:
 *   The static factory methods use mutable ArrayList so that callers
 *   can append to the returned object (e.g. adding audit trail entries
 *   after construction) without hitting UnsupportedOperationException.
 *   List.of() is intentionally avoided here.
 *
 * Validity contract:
 *   isValid() requires BOTH active=true AND status=ACTIVE. The two fields
 *   can legitimately diverge (e.g. an admin sets active=false on an ACTIVE
 *   user to temporarily suspend permission resolution without changing their
 *   status). Both conditions must be true for permissions to be considered
 *   usable.
 *
 * @version 2.0
 */
@Data
@Builder
public class PermissionData {

    // -------------------------------------------------------------------------
    // Core fields
    // -------------------------------------------------------------------------

    /** User ID this permission data belongs to. */
    private String userId;

    /** User email for reference and display. */
    private String email;

    /**
     * Role names assigned to this user.
     * Mutable — use ArrayList so callers can append without exception.
     */
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    /**
     * Resolved permission strings for this user.
     * Represents effective permissions AFTER role resolution + grants - denials.
     * Mutable — use ArrayList so callers can append without exception.
     */
    @Builder.Default
    private List<String> permissions = new ArrayList<>();

    /** Current user status from the approval workflow. */
    private UserStatus status;

    /**
     * Whether permission resolution is active for this user.
     * Can be false even when status=ACTIVE (e.g. temporary suspension).
     * Both this AND status==ACTIVE must be true for isValid() to return true.
     */
    @Builder.Default
    private boolean active = true;

    /**
     * Optimistic locking version.
     * Increment on every write to detect concurrent modification.
     */
    @Builder.Default
    private int version = 1;

    // -------------------------------------------------------------------------
    // Approval tracking
    // -------------------------------------------------------------------------

    /** ID of the approver who activated these permissions. */
    private String approvedBy;

    /** When approval was granted. */
    private Instant approvedAt;

    /** When permissions became active (may differ from approvedAt on re-activation). */
    private Instant grantedAt;

    // -------------------------------------------------------------------------
    // Hierarchy and metadata
    // -------------------------------------------------------------------------

    /**
     * Role hierarchy snapshot at the time of resolution.
     * Maps role name → list of inherited role names.
     * Example: {"ADMIN" → ["MANAGER", "USER"]}
     */
    @Builder.Default
    private Map<String, List<String>> roleHierarchy = new HashMap<>();

    /**
     * Permission resolution metadata.
     * Stores source information, resolution timestamp, resolver version, etc.
     * Example keys: "resolvedAt", "resolverVersion", "source"
     */
    @Builder.Default
    private Map<String, Object> permissionMetadata = new HashMap<>();

    // -------------------------------------------------------------------------
    // Audit trail
    // -------------------------------------------------------------------------

    /**
     * Ordered list of permission change events for this user.
     *
     * Each entry is a typed AuditEntry rather than Map<String, String> —
     * Map<String, String> cannot hold Instant timestamps without string
     * conversion, loses type safety, and has no schema enforcement.
     *
     * Entries are appended in chronological order; most recent is last.
     */
    @Builder.Default
    private List<AuditEntry> auditTrail = new ArrayList<>();

    // -------------------------------------------------------------------------
    // Validity and state checks
    // -------------------------------------------------------------------------

    /**
     * Whether this permission data represents a usable, active permission set.
     *
     * Both conditions must be true:
     *   1. active=true    — permission resolution not suspended
     *   2. status=ACTIVE  — user is in the ACTIVE workflow state
     *   3. permissions is non-null and non-empty
     *
     * Either condition being false means the user should not receive
     * permissions in their JWT regardless of what the permissions list contains.
     */
    public boolean isValid() {
        return active
                && status == UserStatus.ACTIVE
                && permissions != null
                && !permissions.isEmpty();
    }

    /**
     * Whether this user is pending any approval action.
     */
    public boolean isPending() {
        return status == UserStatus.PENDING_APPROVAL;
    }

    /**
     * Whether this permission data has been explicitly deactivated
     * while the user account remains in ACTIVE status.
     * Used to detect temporary permission suspension.
     */
    public boolean isSuspended() {
        return !active && status == UserStatus.ACTIVE;
    }

    /** Total number of resolved permissions. */
    public int getPermissionCount() {
        return permissions != null ? permissions.size() : 0;
    }

    /** Total number of assigned roles. */
    public int getRoleCount() {
        return roles != null ? roles.size() : 0;
    }

    /** Whether the resolved permissions include the given permission string. */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    /** Whether the assigned roles include the given role name. */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    // -------------------------------------------------------------------------
    // Audit trail helpers
    // -------------------------------------------------------------------------

    /**
     * Appends an audit entry to the trail.
     *
     * @param action      what happened e.g. "ROLE_ASSIGNED", "PERMISSION_GRANTED"
     * @param performedBy userId or "SYSTEM" of who made the change
     * @param timestamp   when the change occurred
     * @param detail      optional extra context (nullable)
     */
    public void addAuditEntry(
            String action,
            String performedBy,
            Instant timestamp,
            String userId,
            String detail,
            String metadata

    ) {
        if (auditTrail == null) auditTrail = new ArrayList<>();
        auditTrail.add(new AuditEntry(action, performedBy, timestamp, userId, detail, metadata));
    }

    // -------------------------------------------------------------------------
    // Static factory methods
    // -------------------------------------------------------------------------

    /**
     * Creates a PermissionData snapshot for a user who is pending approval.
     * Permissions list is empty; active=false; status=PENDING_APPROVAL.
     *
     * @param userId user ID
     * @param email  user email
     * @param roles  role names already assigned
     * @return pending PermissionData with no active permissions
     */
    public static PermissionData pending(
            String userId,
            String email,
            List<String> roles
    ) {
        return PermissionData.builder()
                .userId(userId)
                .email(email)
                .roles(roles != null ? new ArrayList<>(roles) : new ArrayList<>())
                .permissions(new ArrayList<>())
                .status(UserStatus.PENDING_APPROVAL)
                .active(false)
                .version(1)
                .auditTrail(new ArrayList<>())
                .roleHierarchy(new HashMap<>())
                .permissionMetadata(new HashMap<>())
                .build();
    }

    /**
     * Creates a PermissionData snapshot for a fully approved and active user.
     *
     * @param userId      user ID
     * @param email       user email
     * @param roles       role names assigned
     * @param permissions resolved effective permission strings
     * @param approvedBy  ID of the approver
     * @param approvedAt  when approval was granted
     * @return active PermissionData with populated permissions
     */
    public static PermissionData active(
            String userId,
            String email,
            List<String> roles,
            List<String> permissions,
            String approvedBy,
            Instant approvedAt
    ) {
        return PermissionData.builder()
                .userId(userId)
                .email(email)
                .roles(roles != null ? new ArrayList<>(roles) : new ArrayList<>())
                .permissions(permissions != null ? new ArrayList<>(permissions) : new ArrayList<>())
                .status(UserStatus.ACTIVE)
                .active(true)
                .approvedBy(approvedBy)
                .approvedAt(approvedAt)
                .grantedAt(approvedAt)
                .version(1)
                .auditTrail(new ArrayList<>())
                .roleHierarchy(new HashMap<>())
                .permissionMetadata(new HashMap<>())
                .build();
    }

    /**
     * @deprecated Use {@link #pending(String, String, List)} instead.
     *             Renamed from "empty" to "pending" to better reflect the
     *             user's actual state and avoid confusion with an empty object.
     */
    @Deprecated(since = "2.1", forRemoval = true)
    public static PermissionData empty(String userId, String email, List<String> roles) {
        return pending(userId, email, roles);
    }
}

// -------------------------------------------------------------------------
// Inner: AuditEntry
// -------------------------------------------------------------------------