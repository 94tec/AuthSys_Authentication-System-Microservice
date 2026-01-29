package com.techStack.authSys.models.user;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

/**
 * User Account Status
 *
 * Represents the current state of a user account and defines
 * allowed state transitions and capabilities for each status.
 */
@Getter
public enum UserStatus {

    ACTIVE(
            "Active",
            "Account is active and operational",
            true,   // canAuthenticate
            false,  // terminal
            false   // systemControlled
    ),
    PENDING_APPROVAL(
            "Pending Approval",
            "Registration pending administrator approval",
            false,
            false,
            false
    ),
    REJECTED(
            "Rejected",
            "Registration was rejected",
            false,
            true,   // terminal
            true    // systemControlled
    ),
    SUSPENDED(
            "Suspended",
            "Account temporarily suspended by admin",
            false,
            false,
            false
    ),
    LOCKED(
            "Locked",
            "Account locked due to security concerns",
            false,
            false,
            false
    ),
    DISABLED(
            "Disabled",
            "Account permanently disabled",
            false,
            true,   // terminal
            true    // systemControlled
    ),
    DEACTIVATED(
            "Deactivated",
            "Account deactivated by user request",
            false,
            true,   // terminal (consider if this should be true)
            false
    );

    private final String displayName;
    private final String description;
    private final boolean canAuthenticate;
    private final boolean terminal;
    private final boolean systemControlled;

    UserStatus(
            String displayName,
            String description,
            boolean canAuthenticate,
            boolean terminal,
            boolean systemControlled
    ) {
        this.displayName = displayName;
        this.description = description;
        this.canAuthenticate = canAuthenticate;
        this.terminal = terminal;
        this.systemControlled = systemControlled;
    }

    /* =========================
       Derived Properties
       ========================= */

    public boolean isAdminControlled() {
        return this == SUSPENDED || this == DISABLED || this == REJECTED;
    }

    public boolean isSecurityRelated() {
        return this == LOCKED || this == SUSPENDED;
    }

    public boolean isPending() {
        return this == PENDING_APPROVAL;
    }

    /* =========================
       State Transitions
       ========================= */

    /**
     * Get all valid target statuses that can be transitioned to from this status.
     *
     * @return set of allowed target statuses
     */
    public Set<UserStatus> allowedTransitions() {
        return switch (this) {
            case PENDING_APPROVAL -> EnumSet.of(ACTIVE, REJECTED);
            case ACTIVE -> EnumSet.of(SUSPENDED, LOCKED, DEACTIVATED, DISABLED);
            case LOCKED -> EnumSet.of(ACTIVE, DISABLED);
            case SUSPENDED -> EnumSet.of(ACTIVE, DISABLED);
            case DEACTIVATED -> EnumSet.of(ACTIVE);
            case REJECTED, DISABLED -> EnumSet.noneOf(UserStatus.class);
        };
    }

    /**
     * Determines if transition from this status to target status is allowed.
     *
     * @param target the desired status to transition to
     * @return true if transition is allowed
     */
    public boolean canTransitionTo(@NotNull UserStatus target) {
        return allowedTransitions().contains(target);
    }

    /* =========================
       Resolution Helpers
       ========================= */

    /**
     * Attempts to resolve a status from a case-insensitive name.
     *
     * @param name the status name (case-insensitive)
     * @return Optional containing the status if found, empty otherwise
     */
    public static Optional<UserStatus> fromName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }

        try {
            return Optional.of(UserStatus.valueOf(name.toUpperCase().trim()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * Attempts to resolve a status from its display name.
     *
     * @param displayName the display name
     * @return Optional containing the status if found, empty otherwise
     */
    public static Optional<UserStatus> fromDisplayName(String displayName) {
        if (displayName == null || displayName.isBlank()) {
            return Optional.empty();
        }

        return Arrays.stream(values())
                .filter(status -> status.displayName.equalsIgnoreCase(displayName.trim()))
                .findFirst();
    }

    /* =========================
       String Representation
       ========================= */

    @Override
    public String toString() {
        return name() + " (" + displayName + ")";
    }
}
