package com.techStack.authSys.authorization.models;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Getter
public enum Roles {

    SUPER_ADMIN(
            "Super Administrator",
            100,
            false,
            true,
            true
    ),

    ADMIN(
            "Administrator",
            90,
            true,
            true,
            true
    ),

    MANAGER(
            "Manager",
            50,
            true,
            false,
            true
    ),

    OPERATOR(
            "Operational Staff",
            30,
            true,
            false,
            true
    ),

    USER(
            "Registered User",
            10,
            true,
            false,
            false
    ),

    GUEST(
            "Guest Visitor",
            1,
            false,
            false,
            false
    );

    private final String description;

    private final int level;

    /**
     * Can be assigned through role-management operations.
     */
    private final boolean assignable;

    /**
     * Core platform role.
     */
    private final boolean systemRole;

    /**
     * Internal staff role.
     */
    private final boolean internalOnly;

    Roles(
            String description,
            int level,
            boolean assignable,
            boolean systemRole,
            boolean internalOnly
    ) {
        this.description = description;
        this.level = level;
        this.assignable = assignable;
        this.systemRole = systemRole;
        this.internalOnly = internalOnly;
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
       Resolution Helpers
       ========================= */

    public static Optional<Roles> fromName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }

        try {
            return Optional.of(
                    Roles.valueOf(name.trim().toUpperCase())
            );
        } catch (IllegalArgumentException ex) {
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

    public static List<Roles> atOrBelow(@NotNull Roles ceiling) {
        return Arrays.stream(values())
                .filter(role -> role.level <= ceiling.level)
                .sorted(
                        Comparator.comparingInt(Roles::getLevel)
                                .reversed()
                )
                .collect(Collectors.toList());
    }

    /**
     * Returns assignable roles below the given actor.
     */
    public static List<Roles> assignableBy(@NotNull Roles actor) {
        return Arrays.stream(values())
                .filter(Roles::isAssignable)
                .filter(actor::hasHigherPrivilegesThan)
                .sorted(
                        Comparator.comparingInt(Roles::getLevel)
                                .reversed()
                )
                .collect(Collectors.toList());
    }

    @Deprecated(since = "2.0", forRemoval = true)
    public String[] getDefaultPermissions() {
        throw new UnsupportedOperationException(
                "Default permissions are DB-backed. " +
                        "Use RolePermissionRepository instead."
        );
    }

    @Override
    public String toString() {
        return name() + " (" + description + ")";
    }

    public int getPriority() {
        return level;
    }
}