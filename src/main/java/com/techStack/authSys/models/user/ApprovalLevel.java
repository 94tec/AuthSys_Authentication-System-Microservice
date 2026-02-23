package com.techStack.authSys.models.user;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

/**
 * Approval Level for Multi-Stage Approval Workflows
 *
 * Represents the current approval state in a hierarchical approval process.
 * Supports single-level (L1), two-level (L1 + L2), or no approval required.
 *
 * Standard workflow:
 *
 *   [USER / MANAGER registration]
 *   NOT_REQUIRED  (auto-approve, terminal)
 *   PENDING_L1    → APPROVED_L1 → PENDING_L2 → APPROVED  (terminal)
 *                ↘ REJECTED  (terminal, available at any stage)
 *
 *   [ADMIN / SUPER_ADMIN registration]
 *   PENDING_L2    → APPROVED  (terminal)
 *                ↘ REJECTED  (terminal)
 *
 * Order values reflect progression; REJECTED uses -1 as a sentinel
 * to indicate it is not part of the happy path.
 */
public enum ApprovalLevel {

    NOT_REQUIRED(
            "Not Required",
            0,
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
            -1,     // sentinel — not part of the happy-path order
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
        this.displayName    = displayName;
        this.order          = order;
        this.terminal       = terminal;
        this.requiresAction = requiresAction;
    }

    // -------------------------------------------------------------------------
    // Getters (no Lombok — enum accessors are trivial and explicit here)
    // -------------------------------------------------------------------------

    public String getDisplayName()  { return displayName;    }
    public int    getOrder()        { return order;          }
    public boolean isTerminal()     { return terminal;       }
    public boolean isRequiresAction() { return requiresAction; }

    // -------------------------------------------------------------------------
    // Derived state predicates
    // -------------------------------------------------------------------------

    /**
     * Whether this level represents a fully approved or no-approval-required state.
     */
    public boolean isApproved() {
        return this == APPROVED || this == NOT_REQUIRED;
    }

    /**
     * Whether this level is awaiting an approval action.
     */
    public boolean isPending() {
        return this == PENDING_L1 || this == PENDING_L2;
    }

    /**
     * Whether this level represents a rejection.
     */
    public boolean isRejected() {
        return this == REJECTED;
    }

    /**
     * Whether this is an intermediate approval state (approved at L1, waiting for L2).
     */
    public boolean isPartiallyApproved() {
        return this == APPROVED_L1;
    }

    /**
     * Returns the pending level number (1 or 2) if currently pending, empty otherwise.
     */
    public Optional<Integer> getPendingLevel() {
        return switch (this) {
            case PENDING_L1 -> Optional.of(1);
            case PENDING_L2 -> Optional.of(2);
            default         -> Optional.empty();
        };
    }

    // -------------------------------------------------------------------------
    // State transitions
    // -------------------------------------------------------------------------

    /**
     * Returns the set of valid levels this state may transition to.
     *
     * Workflow:
     *   NOT_REQUIRED              → (none, terminal)
     *   PENDING_L1   → APPROVED_L1, REJECTED
     *   APPROVED_L1  → PENDING_L2, APPROVED (skip L2), REJECTED
     *   PENDING_L2   → APPROVED, REJECTED
     *   APPROVED     → (none, terminal)
     *   REJECTED     → (none, terminal)
     */
    public Set<ApprovalLevel> allowedTransitions() {
        return switch (this) {
            case NOT_REQUIRED -> EnumSet.noneOf(ApprovalLevel.class);
            case PENDING_L1   -> EnumSet.of(APPROVED_L1, REJECTED);
            case APPROVED_L1  -> EnumSet.of(PENDING_L2, APPROVED, REJECTED);
            case PENDING_L2   -> EnumSet.of(APPROVED, REJECTED);
            case APPROVED,
                 REJECTED     -> EnumSet.noneOf(ApprovalLevel.class);
        };
    }

    /**
     * Whether transitioning from this level to the target level is permitted.
     *
     * @param target the desired approval level to transition to
     * @return true if the transition is in allowedTransitions()
     */
    public boolean canTransitionTo(ApprovalLevel target) {
        if (target == null) return false;
        return allowedTransitions().contains(target);
    }

    /**
     * Returns the next level in the standard happy-path workflow.
     * Empty for terminal states and APPROVED_L1 (which has two possible next states).
     */
    public Optional<ApprovalLevel> getNextLevel() {
        return switch (this) {
            case PENDING_L1  -> Optional.of(APPROVED_L1);
            case APPROVED_L1 -> Optional.of(PENDING_L2);
            case PENDING_L2  -> Optional.of(APPROVED);
            default          -> Optional.empty();
        };
    }

    // -------------------------------------------------------------------------
    // Approval capability helpers
    // -------------------------------------------------------------------------

    /**
     * Whether an approver at the given numeric level can act on this approval level.
     *
     * @param approverLevel the approver's level (1 = L1 approver, 2 = L2 approver)
     * @return true if the approver can act
     */
    public boolean canBeApprovedByLevel(int approverLevel) {
        return switch (this) {
            case PENDING_L1 -> approverLevel >= 1;
            case PENDING_L2 -> approverLevel >= 2;
            default         -> false;
        };
    }

    /**
     * Whether this level has progressed further along the happy path than the given level.
     *
     * Rules:
     *  - REJECTED is not considered "beyond" anything — it is off the happy path.
     *  - NOT_REQUIRED (order=0) participates in comparison normally; a level
     *    with order > 0 has progressed beyond NOT_REQUIRED.
     *  - If the given level is REJECTED, comparison is undefined → returns false.
     *
     * Examples:
     *   APPROVED.hasProgressedBeyond(PENDING_L1)   → true  (4 > 1)
     *   PENDING_L1.hasProgressedBeyond(APPROVED)   → false (1 > 4 is false)
     *   APPROVED.hasProgressedBeyond(NOT_REQUIRED) → true  (4 > 0)
     *   REJECTED.hasProgressedBeyond(PENDING_L1)   → false (sentinel, off happy path)
     *   APPROVED.hasProgressedBeyond(REJECTED)     → false (reference is off happy path)
     *
     * @param other the level to compare against
     * @return true if this level's order is strictly greater than other's order,
     *         with REJECTED on either side always returning false
     */
    public boolean hasProgressedBeyond(ApprovalLevel other) {
        if (other == null)        return false;
        if (this  == REJECTED)    return false;  // off happy path
        if (other == REJECTED)    return false;  // reference point is off happy path
        return this.order > other.order;
    }

    // -------------------------------------------------------------------------
    // Resolution helpers
    // -------------------------------------------------------------------------

    /**
     * Resolves an ApprovalLevel from a case-insensitive name string.
     * Returns empty Optional instead of throwing for null/blank/unknown input.
     *
     * @param name the enum name (case-insensitive), e.g. "pending_l1"
     * @return Optional containing the matched level, or empty if not found
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
     * Resolves an ApprovalLevel from its display name string.
     * Returns empty Optional for null/blank/unmatched input.
     *
     * @param displayName the human-readable display name, e.g. "Pending Level 1 Approval"
     * @return Optional containing the matched level, or empty if not found
     */
    public static Optional<ApprovalLevel> fromDisplayName(String displayName) {
        if (displayName == null || displayName.isBlank()) {
            return Optional.empty();
        }
        String trimmed = displayName.trim();
        return Arrays.stream(values())
                .filter(level -> level.displayName.equalsIgnoreCase(trimmed))
                .findFirst();
    }

    /**
     * Resolves an ApprovalLevel by its order value.
     * Returns empty Optional if no level has that order.
     *
     * Note: REJECTED has order=-1. NOT_REQUIRED has order=0.
     *
     * @param order the order value to look up
     * @return Optional containing the matched level, or empty if not found
     */
    public static Optional<ApprovalLevel> fromOrder(int order) {
        return Arrays.stream(values())
                .filter(level -> level.order == order)
                .findFirst();
    }

    // -------------------------------------------------------------------------
    // Set helpers
    // -------------------------------------------------------------------------

    /**
     * Returns all levels that require an approval action (i.e. pending states).
     */
    public static Set<ApprovalLevel> getPendingLevels() {
        return EnumSet.of(PENDING_L1, PENDING_L2);
    }

    /**
     * Returns all terminal levels (no further transitions possible).
     *
     * Fix from original: used a stream + Collectors.toCollection() which is
     * unnecessarily verbose. EnumSet.of() is direct, type-safe, and O(1).
     */
    public static Set<ApprovalLevel> getTerminalLevels() {
        return EnumSet.of(NOT_REQUIRED, APPROVED, REJECTED);
    }

    /**
     * Returns all levels that represent a fully resolved (non-pending) state.
     * Useful for querying Firestore for users who no longer need action.
     */
    public static Set<ApprovalLevel> getResolvedLevels() {
        return EnumSet.of(NOT_REQUIRED, APPROVED_L1, APPROVED, REJECTED);
    }

    // -------------------------------------------------------------------------
    // String representation
    // -------------------------------------------------------------------------

    @Override
    public String toString() {
        return name() + " (" + displayName + ")";
    }
}