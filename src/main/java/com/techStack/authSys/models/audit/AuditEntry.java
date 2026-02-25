package com.techStack.authSys.models.audit;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Typed audit trail entry for PermissionData.
 *
 * Replaces Map<String, String> in the auditTrail list.
 *
 * Design decisions:
 *   - performedAt is Instant, not String — no parsing needed at read time
 *   - action is a String not enum — new action types can be added without
 *     code changes (stored in Firestore, read back as-is)
 *   - targetId is nullable — some actions have no specific target
 *     (e.g. "PERMISSIONS_RELOADED" applies to all users)
 *   - reason is nullable — only set when context is meaningful
 *     (e.g. rejection reason, lock reason)
 *   - metadata is a String — arbitrary extra context serialized as JSON
 *     string to keep Firestore field types flat
 *
 * Firestore compatibility:
 *   All fields are primitives, Strings, or Instant — no nested objects,
 *   no Sets, no Map<String, Object>. Safe to serialize directly.
 *
 * Common action values:
 *   USER_CREATED          — user registered for the first time
 *   USER_APPROVED         — approval workflow completed
 *   USER_REJECTED         — approval rejected
 *   USER_DEACTIVATED      — account deactivated
 *   USER_RESTORED         — account restored after deactivation
 *   ROLE_ASSIGNED         — role added to user
 *   ROLE_REMOVED          — role removed from user
 *   PERMISSION_GRANTED    — explicit permission grant added
 *   PERMISSION_REVOKED    — explicit permission revoked
 *   DENIAL_ADDED          — denial added to strip a role permission
 *   DENIAL_REMOVED        — denial removed
 *   ACCOUNT_LOCKED        — account locked (brute force / manual)
 *   ACCOUNT_UNLOCKED      — account unlocked
 *   PASSWORD_CHANGED      — password updated
 *   PASSWORD_RESET        — password reset via token
 *   MFA_ENABLED           — MFA turned on
 *   MFA_DISABLED          — MFA turned off
 *   PERMISSIONS_RELOADED  — admin triggered yaml → Firestore reload
 *   LOGIN_SUCCESS         — successful login recorded
 *   LOGIN_FAILED          — failed login attempt recorded
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditEntry {

    /**
     * What happened.
     * Use the action constants documented in the class Javadoc.
     * e.g. "USER_CREATED", "ROLE_ASSIGNED", "PERMISSION_GRANTED"
     */
    private String action;

    /**
     * Firebase UID of the user who performed this action.
     * "SYSTEM" for automated actions (seeder, registration workflow).
     * "UNKNOWN" if the actor cannot be determined.
     */
    private String performedBy;

    /**
     * When the action occurred.
     * Stored as Instant — Firestore serializes this as a Timestamp.
     */
    private Instant performedAt;

    /**
     * Optional: the ID of the object this action targeted.
     * For role actions: the role name e.g. "DESIGNER"
     * For permission actions: the permission string e.g. "portfolio:publish"
     * For user actions: the affected user's Firebase UID
     * Null for actions with no specific target.
     */
    private String targetId;

    /**
     * Optional: human-readable reason for the action.
     * e.g. rejection reason, lock reason, why a permission was granted.
     * Null when no reason context is needed.
     */
    private String reason;

    /**
     * Optional: additional context as a JSON string.
     * Keeps Firestore field types flat — no nested maps.
     * e.g. '{"previousRole":"USER","newRole":"DESIGNER","approvalLevel":"PENDING_L1"}'
     * Null when no extra context is needed.
     */
    private String metadata;

    /* =========================
       Static Factory Methods
       ========================= */

    /**
     * User created during registration.
     */
    public static AuditEntry userCreated(String performedBy, Instant now) {
        return AuditEntry.builder()
            .action("USER_CREATED")
            .performedBy(performedBy)
            .performedAt(now)
            .build();
    }

    /**
     * User approved by an admin.
     */
    public static AuditEntry userApproved(String approvedBy, Instant now) {
        return AuditEntry.builder()
            .action("USER_APPROVED")
            .performedBy(approvedBy)
            .performedAt(now)
            .build();
    }

    /**
     * User rejected by an admin.
     */
    public static AuditEntry userRejected(String rejectedBy,
                                           String reason,
                                           Instant now) {
        return AuditEntry.builder()
            .action("USER_REJECTED")
            .performedBy(rejectedBy)
            .performedAt(now)
            .reason(reason)
            .build();
    }

    /**
     * Role assigned to user.
     */
    public static AuditEntry roleAssigned(String assignedBy,
                                           String roleName,
                                           Instant now) {
        return AuditEntry.builder()
            .action("ROLE_ASSIGNED")
            .performedBy(assignedBy)
            .performedAt(now)
            .targetId(roleName)
            .build();
    }

    /**
     * Role removed from user.
     */
    public static AuditEntry roleRemoved(String removedBy,
                                          String roleName,
                                          Instant now) {
        return AuditEntry.builder()
            .action("ROLE_REMOVED")
            .performedBy(removedBy)
            .performedAt(now)
            .targetId(roleName)
            .build();
    }

    /**
     * Explicit permission granted to user.
     */
    public static AuditEntry permissionGranted(String grantedBy,
                                                String permission,
                                                Instant now) {
        return AuditEntry.builder()
            .action("PERMISSION_GRANTED")
            .performedBy(grantedBy)
            .performedAt(now)
            .targetId(permission)
            .build();
    }

    /**
     * Permission revoked — either from grants list or via denial.
     *
     * @param method "grant_removed" or "denial_added"
     */
    public static AuditEntry permissionRevoked(String revokedBy,
                                                String permission,
                                                String method,
                                                Instant now) {
        return AuditEntry.builder()
            .action("PERMISSION_REVOKED")
            .performedBy(revokedBy)
            .performedAt(now)
            .targetId(permission)
            .reason(method)
            .build();
    }

    /**
     * Account locked.
     */
    public static AuditEntry accountLocked(String lockedBy,
                                            String reason,
                                            String lockType,
                                            Instant now) {
        return AuditEntry.builder()
            .action("ACCOUNT_LOCKED")
            .performedBy(lockedBy != null ? lockedBy : "SYSTEM")
            .performedAt(now)
            .reason(reason)
            .metadata("{\"lockType\":\"" + lockType + "\"}")
            .build();
    }

    /**
     * Account unlocked.
     */
    public static AuditEntry accountUnlocked(String unlockedBy, Instant now) {
        return AuditEntry.builder()
            .action("ACCOUNT_UNLOCKED")
            .performedBy(unlockedBy != null ? unlockedBy : "SYSTEM")
            .performedAt(now)
            .build();
    }

    /**
     * Password changed.
     */
    public static AuditEntry passwordChanged(String changedBy,
                                              String changeReason,
                                              Instant now) {
        return AuditEntry.builder()
            .action("PASSWORD_CHANGED")
            .performedBy(changedBy != null ? changedBy : "SYSTEM")
            .performedAt(now)
            .reason(changeReason)
            .build();
    }

    /**
     * Successful login recorded.
     */
    public static AuditEntry loginSuccess(String userId,
                                           String ip,
                                           Instant now) {
        return AuditEntry.builder()
            .action("LOGIN_SUCCESS")
            .performedBy(userId)
            .performedAt(now)
            .metadata("{\"ip\":\"" + (ip != null ? ip : "unknown") + "\"}")
            .build();
    }

    /**
     * Failed login attempt.
     */
    public static AuditEntry loginFailed(String userId,
                                          String ip,
                                          Instant now) {
        return AuditEntry.builder()
            .action("LOGIN_FAILED")
            .performedBy(userId != null ? userId : "UNKNOWN")
            .performedAt(now)
            .metadata("{\"ip\":\"" + (ip != null ? ip : "unknown") + "\"}")
            .build();
    }

    /**
     * System action — no specific actor.
     * Used for seeder, automated workflows, etc.
     */
    public static AuditEntry system(String action, Instant now) {
        return AuditEntry.builder()
            .action(action)
            .performedBy("SYSTEM")
            .performedAt(now)
            .build();
    }
}