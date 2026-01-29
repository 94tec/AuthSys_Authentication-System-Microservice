package com.techStack.authSys.models.user;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.Optional;

/**
 * User Roles with hierarchical privilege levels
 *
 * Higher level = More privileges
 * Used for role hierarchy, access control, and upgrade validation
 */
@Getter
public enum Roles {

    SUPER_ADMIN("Super Administrator", 100),
    ADMIN("Administrator", 50),
    MANAGER("Manager", 30),
    USER("Standard User", 10);

    private final String description;
    private final int level;

    Roles(String description, int level) {
        this.description = description;
        this.level = level;
    }

    /* =========================
       Hierarchy Checks
       ========================= */

    /**
     * Checks if this role has equal or greater privileges than another role.
     *
     * @param other the role to compare against
     * @return true if this role's level >= other's level
     */
    public boolean hasAtLeastPrivilegesOf(@NotNull Roles other) {
        return this.level >= other.level;
    }

    /**
     * Checks if this role has strictly higher privileges than another role.
     *
     * @param other the role to compare against
     * @return true if this role's level > other's level
     */
    public boolean hasHigherPrivilegesThan(@NotNull Roles other) {
        return this.level > other.level;
    }

    /* =========================
       Upgrade Rules
       ========================= */

    /**
     * Determines if the current role can request an upgrade to the target role.
     *
     * Business Rules:
     * - Cannot upgrade to same or lower level
     * - USER cannot directly upgrade to ADMIN (must go through MANAGER)
     * - Add more blocked paths as needed
     *
     * @param target the desired role to upgrade to
     * @return true if upgrade path is allowed
     */
    public boolean canRequestUpgradeTo(@NotNull Roles target) {
        // Cannot upgrade to same or lower level
        if (this.level >= target.level) {
            return false;
        }

        // Explicitly blocked upgrade paths
        if (this == USER && target == ADMIN) {
            return false;
        }

        // Add more business logic here as needed
        // Example: if (this == MANAGER && target == SUPER_ADMIN) return false;

        return true;
    }

    /* =========================
       Resolution Helpers
       ========================= */

    /**
     * Attempts to resolve a role from a case-insensitive name.
     *
     * @param name the role name (case-insensitive)
     * @return Optional containing the role if found, empty otherwise
     */
    public static Optional<Roles> fromName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }

        try {
            return Optional.of(Roles.valueOf(name.toUpperCase().trim()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * Gets a role by its numeric level.
     *
     * @param level the privilege level
     * @return Optional containing the role if found, empty otherwise
     */
    public static Optional<Roles> fromLevel(int level) {
        return Arrays.stream(values())
                .filter(role -> role.level == level)
                .findFirst();
    }

    /* =========================
       Default Permissions
       ========================= */

    /**
     * Get default permissions for this role.
     * Note: In production, permissions should come from permissions.yaml or database
     *
     * @return array of default permission strings
     */
    public String[] getDefaultPermissions() {
        return switch (this) {
            case SUPER_ADMIN -> new String[]{"*:*"};
            case ADMIN -> new String[]{
                    "read:users", "write:users", "delete:users",
                    "read:audit_logs", "manage:roles"
            };
            case MANAGER -> new String[]{
                    "read:team_data", "write:team_data",
                    "read:team_members", "approve:requests"
            };
            case USER -> new String[]{
                    "read:own_profile", "write:own_profile",
                    "read:public_data"
            };
        };
    }

    /* =========================
         String Representation
    ========================= */
    @Override
    public String toString() {
        return name() + " (" + description + ")";
    }

    /** **
     * Priority accessor for compatibility with User class.
     * * @return the privilege level of this role
     * */
    public int getPriority() {
        return this.level;
    }
}
