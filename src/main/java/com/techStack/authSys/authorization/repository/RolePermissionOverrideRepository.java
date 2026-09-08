package com.techStack.authSys.authorization.repository;

import com.techStack.authSys.authorization.models.RolePermissionOverride;
import com.techStack.authSys.authorization.models.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * RolePermissionOverrideRepository
 *
 * All methods are called from RoleAccessManagementService — no extras.
 *
 * Caller map:
 *
 *   resolveBlocking()           → findByRole(role)
 *   setPermissionOverride()     → findByRoleAndPermission(role, permission)
 *   setPermissionOverride()     → save(override)
 *   removeOverride()            → deleteByRoleAndPermission(role, permission)
 *   getOverridesForRole()       → findByRole(role)
 *
 * Additional read methods used by the controller (admin UI):
 *   getAllOverrides()            → findAll()   [inherited]
 *   getOverridesByPermission()  → findByPermission(permission)
 *   countGrantedForRole()       → countByRoleAndGrantedTrue(role)
 *   countRevokedForRole()       → countByRoleAndGrantedFalse(role)
 */
@Repository
public interface RolePermissionOverrideRepository extends JpaRepository<RolePermissionOverride, Long> {

    // ── Called by RoleAccessManagementService ─────────────────────────────────

    /**
     * Returns all overrides for a role — used in resolveBlocking() to build
     * the effective permission set and in getOverridesForRole() for the API.
     */
    List<RolePermissionOverride> findByRole(Roles role);

    /**
     * Find an existing override for a role+permission pair.
     * Used in setPermissionOverride() to update-or-create:
     *
     *   overrideRepository.findByRoleAndPermission(role, permission)
     *       .orElseGet(() -> RolePermissionOverride.builder()
     *               .role(role).permission(permission).build());
     */
    Optional<RolePermissionOverride> findByRoleAndPermission(Roles role, String permission);

    /**
     * Deletes the override row, restoring the PermissionProvider default.
     * Declared @Modifying because Spring Data needs the hint that this
     * mutates data (even though the derived-delete query would work without
     * it in most providers — explicit is safer).
     */
    @Modifying
    @Query("DELETE FROM RolePermissionOverride o WHERE o.role = :role AND o.permission = :permission")
    void deleteByRoleAndPermission(@Param("role") Roles role, @Param("permission") String permission);

    // ── Used by controller / admin API ────────────────────────────────────────

    /**
     * All overrides for a specific permission string — useful for showing
     * "which roles have been granted/revoked 'bookings:cancel'?" in the UI.
     */
    List<RolePermissionOverride> findByPermission(String permission);

    /**
     * All overrides with a given granted value across all roles.
     * Used to list "all custom grants" or "all custom revocations" in one query.
     */
    List<RolePermissionOverride> findByGranted(Boolean granted);

    /**
     * Count of active grants for a role — admin dashboard stat.
     */
    long countByRoleAndGrantedTrue(Roles role);

    /**
     * Count of active revocations for a role — admin dashboard stat.
     */
    long countByRoleAndGrantedFalse(Roles role);

    /**
     * Whether any override exists for this role+permission pair.
     * Used by the controller to show "override active" status without
     * fetching the full object.
     */
    boolean existsByRoleAndPermission(Roles role, String permission);

    /**
     * All overrides set by a specific SUPER_ADMIN UID.
     * Used in the audit view: "show all permission changes made by this admin".
     */
    List<RolePermissionOverride> findBySetBy(String setBy);

    /**
     * All overrides ordered by most recently modified — default list view.
     */
    List<RolePermissionOverride> findAllByOrderByUpdatedAtDesc();
}
