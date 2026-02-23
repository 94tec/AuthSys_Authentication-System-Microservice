package com.techStack.authSys.models.user;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * User Roles with hierarchical privilege levels.
 *
 * Higher level = More privileges.
 * Used for role hierarchy, access control, and upgrade validation.
 *
 * Levels align with the roles DB table:
 *   SUPER_ADMIN=100, ADMIN=90, DESIGNER=70, MANAGER=50, USER=10, GUEST=1
 *
 * NOTE: Default permissions are now DB-backed.
 * See V8__seed_roles.sql and V10__seed_role_permissions.sql.
 */
@Getter
public enum Roles {

    SUPER_ADMIN("Super Administrator", 100),
    ADMIN("Administrator",             90),
    DESIGNER("Fashion Designer",       70),
    MANAGER("Manager",                 50),
    USER("Standard User",              10),
    GUEST("Guest Visitor",              1);

    private final String description;
    private final int level;

    Roles(String description, int level) {
        this.description = description;
        this.level = level;
    }

    /* =========================
       Hierarchy Checks
       ========================= */

    public boolean hasAtLeastPrivilegesOf(@NotNull Roles other) {
        return this.level >= other.level;
    }

    public boolean hasHigherPrivilegesThan(@NotNull Roles other) {
        return this.level > other.level;
    }

    /* =========================
       Upgrade Rules
       ========================= */

    /**
     * Determines if the current role can request an upgrade to the target role.
     *
     * Allowed paths:
     *   GUEST    → USER only
     *   USER     → DESIGNER or MANAGER (not ADMIN or SUPER_ADMIN directly)
     *   DESIGNER → MANAGER only
     *   MANAGER  → ADMIN only
     *   ADMIN    → SUPER_ADMIN only
     */
    public boolean canRequestUpgradeTo(@NotNull Roles target) {
        if (this.level >= target.level)              return false;
        if (this == GUEST    && target != USER)      return false;
        if (this == USER     && target == ADMIN)     return false;
        if (this == USER     && target == SUPER_ADMIN) return false;
        if (this == DESIGNER && target == ADMIN)     return false;
        if (this == DESIGNER && target == SUPER_ADMIN) return false;
        if (this == MANAGER  && target == SUPER_ADMIN) return false;
        return true;
    }

    /* =========================
       Resolution Helpers
       ========================= */

    public static Optional<Roles> fromName(String name) {
        if (name == null || name.isBlank()) return Optional.empty();
        try {
            return Optional.of(Roles.valueOf(name.toUpperCase().trim()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public static Optional<Roles> fromLevel(int level) {
        return Arrays.stream(values())
                .filter(role -> role.level == level)
                .findFirst();
    }

    public static boolean isValid(String name) {
        return fromName(name).isPresent();
    }

    /**
     * Returns all roles at or below the given ceiling, highest first.
     * Useful for delegation checks — an ADMIN can only assign roles below their own.
     */
    public static List<Roles> atOrBelow(@NotNull Roles ceiling) {
        return Arrays.stream(values())
                .filter(r -> r.level <= ceiling.level)
                .sorted(Comparator.comparingInt(Roles::getLevel).reversed())
                .collect(Collectors.toList());
    }

    /* =========================
       Deprecated
       ========================= */

    /**
     * @deprecated Replaced by DB-backed role-permission mapping.
     * Use RolePermissionRepository.findPermissionsByRoleName() instead.
     */
    @Deprecated(since = "2.0", forRemoval = true)
    public String[] getDefaultPermissions() {
        throw new UnsupportedOperationException(
                "getDefaultPermissions() is removed. " +
                        "Use RolePermissionRepository.findPermissionsByRoleName() instead."
        );
    }

    /* =========================
       String Representation
       ========================= */

    @Override
    public String toString() {
        return name() + " (" + description + ")";
    }

    /** Priority accessor for compatibility. */
    public int getPriority() {
        return this.level;
    }
}