package com.techStack.authSys.authorization.models;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

/**
 * A persisted override that layers on top of PermissionProvider's hard-coded
 * role-permission defaults.
 *
 * Each row says: "for this role, the permission string is either
 * explicitly GRANTED (true) or explicitly REVOKED (false)."
 *
 * Used by RoleAccessManagementService.resolveBlocking():
 *
 *   for (RolePermissionOverride override : overrideRepository.findByRole(role)) {
 *       if (Boolean.TRUE.equals(override.getGranted())) {
 *           permissions.add(override.getPermission());
 *       } else {
 *           permissions.remove(override.getPermission());
 *       }
 *   }
 *
 * Design:
 *   - (role, permission) is unique — one override row per role+permission pair.
 *   - SUPER_ADMIN rows are blocked at the service layer; the DB constraint
 *     exists as a belt-and-suspenders guard.
 *   - setBy / reason provide an audit trail directly on the row for
 *     quick "who changed what and why" queries without hitting the audit log.
 *
 * Storage: PostgreSQL via JPA (same datasource as Tour/Booking modules).
 * Firestore is NOT used here — overrides are part of the relational
 * auth config, not the user profile document.
 */
@Entity
@Table(
        name = "role_permission_overrides",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uq_role_permission",
                        columnNames = {"role", "permission"}
                )
        },
        indexes = {
                @Index(name = "idx_rpo_role", columnList = "role"),
                @Index(name = "idx_rpo_permission", columnList = "permission"),
                @Index(name = "idx_rpo_granted", columnList = "granted")
        }
)
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@org.hibernate.annotations.Check(
        constraints = "role <> 'SUPER_ADMIN'"
)
public class RolePermissionOverride {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id;

    // ── Core fields ───────────────────────────────────────────────────────────

    /**
     * The role this override applies to.
     * Stored as the enum name string (e.g. "ADMIN", "MANAGER").
     * SUPER_ADMIN is blocked at service layer; the check constraint below
     * adds a DB-level guard.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 30)
    private Roles role;

    /**
     * The permission string being overridden.
     * Uses the namespace:action convention already established in PermissionProvider.
     * e.g. "tours:write", "bookings:cancel", "payments:refund"
     */
    @Column(name = "permission", nullable = false, length = 150)
    private String permission;

    /**
     * true  = explicitly GRANT this permission to the role
     * false = explicitly REVOKE this permission from the role
     *
     * Uses Boolean (not boolean) so the service can check
     * Boolean.TRUE.equals(override.getGranted()) safely.
     */
    @Column(name = "granted", nullable = false)
    private Boolean granted;

    // ── Audit fields (inline — not from BaseEntity, no UUID PK needed) ───────

    /**
     * Firebase UID of the SUPER_ADMIN who set this override.
     * Matches User.id in the Firestore user collection.
     */
    @Column(name = "set_by", nullable = false, length = 128)
    private String setBy;

    /**
     * Mandatory reason for every override — prevents undocumented permission changes.
     * e.g. "Temporary access granted for marketing campaign Q4 2025"
     */
    @Column(name = "reason", nullable = false, length = 500)
    private String reason;

    @CreatedDate
    @Column(name = "created_at", updatable = false, nullable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    // ── Convenience ───────────────────────────────────────────────────────────

    /**
     * Human-readable summary for logging and API responses.
     * e.g. "GRANT tours:write to ADMIN (by uid123)"
     */
    public String toAuditString() {
        return String.format("%s '%s' for role %s (set by: %s, reason: %s)",
                Boolean.TRUE.equals(granted) ? "GRANT" : "REVOKE",
                permission, role != null ? role.name() : "null",
                setBy, reason);
    }
}
