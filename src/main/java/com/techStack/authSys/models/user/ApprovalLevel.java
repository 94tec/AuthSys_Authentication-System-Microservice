package com.techStack.authSys.models.user;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

/**
 * Approval Level for Multi-Stage Approval Workflows
 *
 * Represents the current approval state in a hierarchical approval process.
 * Supports single-level (L1), two-level (L1 + L2), or no approval required.
 */
@Getter
public enum ApprovalLevel {

    NOT_REQUIRED(
            "Not Required",
            0,      // order
            true,   // terminal
            false   // requiresAction
    ),

    PENDING_L1(
            "Pending Level 1 Approval",
            1,
            false,
            true    // requiresAction
    ),

    APPROVED_L1(
            "Level 1 Approved",
            2,
            false,
            false
    ),

    PENDING_L2(
            "Pending Level 2 Approval",
            3,
            false,
            true    // requiresAction
    ),

    APPROVED(
            "Approved",
            4,
            true,   // terminal
            false
    ),

    REJECTED(
            "Rejected",
            -1,
            true,   // terminal
            false
    );

    private final String displayName;
    private final int order;
    private final boolean terminal;
    private final boolean requiresAction;

    ApprovalLevel(
            String displayName,
            int order,
            boolean terminal,
            boolean requiresAction
    ) {
        this.displayName = displayName;
        this.order = order;
        this.terminal = terminal;
        this.requiresAction = requiresAction;
    }

    /* =========================
       Derived Properties
       ========================= */

    /**
     * Check if this approval level represents a fully approved state.
     *
     * @return true if approved or approval not required
     */
    public boolean isApproved() {
        return this == APPROVED || this == NOT_REQUIRED;
    }

    /**
     * Check if this approval level is awaiting action.
     *
     * @return true if pending any approval level
     */
    public boolean isPending() {
        return this == PENDING_L1 || this == PENDING_L2;
    }

    /**
     * Check if this approval level represents a rejection.
     *
     * @return true if rejected
     */
    public boolean isRejected() {
        return this == REJECTED;
    }

    /**
     * Check if this is an intermediate approval state.
     *
     * @return true if approved at L1 but awaiting L2
     */
    public boolean isPartiallyApproved() {
        return this == APPROVED_L1;
    }

    /**
     * Get the approval level number (1 or 2) if pending.
     *
     * @return Optional containing level number, empty if not pending
     */
    public Optional<Integer> getPendingLevel() {
        return switch (this) {
            case PENDING_L1 -> Optional.of(1);
            case PENDING_L2 -> Optional.of(2);
            default -> Optional.empty();
        };
    }

    /* =========================
       State Transitions
       ========================= */

    /**
     * Get all valid target approval levels that can be transitioned to.
     *
     * Workflow:
     * - NOT_REQUIRED: Terminal, no transitions
     * - PENDING_L1 → APPROVED_L1, REJECTED
     * - APPROVED_L1 → PENDING_L2, REJECTED (can skip L2 or proceed to L2)
     * - PENDING_L2 → APPROVED, REJECTED
     * - APPROVED, REJECTED: Terminal, no transitions
     *
     * @return set of allowed target approval levels
     */
    public Set<ApprovalLevel> allowedTransitions() {
        return switch (this) {
            case NOT_REQUIRED -> EnumSet.noneOf(ApprovalLevel.class);
            case PENDING_L1 -> EnumSet.of(APPROVED_L1, REJECTED);
            case APPROVED_L1 -> EnumSet.of(PENDING_L2, APPROVED, REJECTED);
            case PENDING_L2 -> EnumSet.of(APPROVED, REJECTED);
            case APPROVED, REJECTED -> EnumSet.noneOf(ApprovalLevel.class);
        };
    }

    /**
     * Determines if transition from this level to target level is allowed.
     *
     * @param target the desired approval level to transition to
     * @return true if transition is allowed
     */
    public boolean canTransitionTo(@NotNull ApprovalLevel target) {
        return allowedTransitions().contains(target);
    }

    /**
     * Get the next approval level in the standard workflow.
     *
     * @return Optional containing next level, empty if terminal or non-standard
     */
    public Optional<ApprovalLevel> getNextLevel() {
        return switch (this) {
            case PENDING_L1 -> Optional.of(APPROVED_L1);
            case APPROVED_L1 -> Optional.of(PENDING_L2);
            case PENDING_L2 -> Optional.of(APPROVED);
            default -> Optional.empty();
        };
    }

    /* =========================
       Workflow Helpers
       ========================= */

    /**
     * Determine if this approval level can be approved by a given role level.
     *
     * @param approverLevel the level of the approver (1 or 2)
     * @return true if approver can act on this level
     */
    public boolean canBeApprovedByLevel(int approverLevel) {
        return switch (this) {
            case PENDING_L1 -> approverLevel >= 1;
            case PENDING_L2 -> approverLevel >= 2;
            default -> false;
        };
    }

    /**
     * Check if this level has progressed beyond a given approval level.
     *
     * @param level the level to compare against
     * @return true if current order > given level's order
     */
    public boolean hasProgressedBeyond(@NotNull ApprovalLevel level) {
        // Rejected is special case - not considered "beyond" anything
        if (this == REJECTED || level == REJECTED) {
            return false;
        }
        return this.order > level.order;
    }

    /* =========================
       Resolution Helpers
       ========================= */

    /**
     * Attempts to resolve an approval level from a case-insensitive name.
     *
     * @param name the approval level name (case-insensitive)
     * @return Optional containing the level if found, empty otherwise
     */
    public static Optional<ApprovalLevel> fromName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }

        try {
            return Optional.of(ApprovalLevel.valueOf(name.toUpperCase().trim()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * Attempts to resolve an approval level from its display name.
     *
     * @param displayName the display name
     * @return Optional containing the level if found, empty otherwise
     */
    public static Optional<ApprovalLevel> fromDisplayName(String displayName) {
        if (displayName == null || displayName.isBlank()) {
            return Optional.empty();
        }

        return Arrays.stream(values())
                .filter(level -> level.displayName.equalsIgnoreCase(displayName.trim()))
                .findFirst();
    }

    /**
     * Get approval level by order value.
     *
     * @param order the order value
     * @return Optional containing the level if found, empty otherwise
     */
    public static Optional<ApprovalLevel> fromOrder(int order) {
        return Arrays.stream(values())
                .filter(level -> level.order == order)
                .findFirst();
    }

    /**
     * Get all approval levels that require action.
     *
     * @return set of levels requiring approval action
     */
    public static Set<ApprovalLevel> getPendingLevels() {
        return EnumSet.of(PENDING_L1, PENDING_L2);
    }

    /**
     * Get all terminal approval levels.
     *
     * @return set of terminal levels
     */
    public static Set<ApprovalLevel> getTerminalLevels() {
        return Arrays.stream(values())
                .filter(ApprovalLevel::isTerminal)
                .collect(java.util.stream.Collectors.toCollection(() -> EnumSet.noneOf(ApprovalLevel.class)));
    }

    /* =========================
       String Representation
       ========================= */

    @Override
    public String toString() {
        return name() + " (" + displayName + ")";
    }
}
