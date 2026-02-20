package com.techStack.authSys.util.auth;


import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Admin Authorization Utilities
 *
 * Centralized role-based authorization logic for admin operations.
 * Implements hierarchical permission model: SUPER_ADMIN > ADMIN > MANAGER > USER
 *
 * @author TechStack Security Team
 * @version 1.0
 */
public final class AdminAuthorizationUtils {

    private AdminAuthorizationUtils() {
        throw new UnsupportedOperationException("Utility class");
    }

    /* =========================
       Role Checks
       ========================= */

    public static boolean isSuperAdmin(Roles role) {
        return role == Roles.SUPER_ADMIN;
    }

    public static boolean isAdmin(Roles role) {
        return role == Roles.ADMIN || role == Roles.SUPER_ADMIN;
    }

    public static boolean canApproveUsers(Roles role) {
        return role == Roles.ADMIN || role == Roles.SUPER_ADMIN;
    }

    public static boolean canRejectUsers(Roles role) {
        return role == Roles.ADMIN || role == Roles.SUPER_ADMIN;
    }

    public static boolean canSuspendUsers(Roles role) {
        return role == Roles.ADMIN || role == Roles.SUPER_ADMIN;
    }

    public static boolean canReactivateUsers(Roles role) {
        return role == Roles.ADMIN || role == Roles.SUPER_ADMIN;
    }

    public static boolean canForcePasswordReset(Roles role) {
        return role == Roles.ADMIN || role == Roles.SUPER_ADMIN;
    }

    public static boolean canViewUsers(Roles role) {
        return role == Roles.ADMIN || role == Roles.SUPER_ADMIN;
    }

    public static boolean canViewStatistics(Roles role) {
        return role == Roles.ADMIN || role == Roles.SUPER_ADMIN;
    }

    /* =========================
       Hierarchical Authority Checks
       ========================= */

    /**
     * Check if performer can manage target user
     *
     * Rules:
     * - SUPER_ADMIN can manage everyone (100% access)
     * - ADMIN can manage USER, MANAGER (75% access)
     * - ADMIN cannot manage ADMIN, SUPER_ADMIN
     */
    public static Mono<Boolean> checkManagementAuthority(User targetUser, Roles performerRole) {
        return Mono.fromCallable(() -> {
            // SUPER_ADMIN has full access
            if (performerRole == Roles.SUPER_ADMIN) {
                return true;
            }

            // ADMIN can manage non-admin users
            if (performerRole == Roles.ADMIN) {
                Set<Roles> targetRoles = targetUser.getRoles();
                boolean hasAdminRole = targetRoles.contains(Roles.ADMIN) ||
                        targetRoles.contains(Roles.SUPER_ADMIN);

                return !hasAdminRole; // Can manage if target is NOT admin
            }

            return false;
        });
    }

    /**
     * Check if performer can view target user
     */
    public static boolean canViewUser(User user, Roles performerRole) {
        // SUPER_ADMIN sees everyone
        if (performerRole == Roles.SUPER_ADMIN) {
            return true;
        }

        // ADMIN sees non-admin users
        if (performerRole == Roles.ADMIN) {
            return !user.getRoles().contains(Roles.ADMIN) &&
                    !user.getRoles().contains(Roles.SUPER_ADMIN);
        }

        return false;
    }

    /**
     * Check role hierarchy
     *
     * @return true if performerRole >= requiredRole
     */
    public static boolean hasRoleLevel(Roles performerRole, Roles requiredRole) {
        return getRoleLevel(performerRole) >= getRoleLevel(requiredRole);
    }

    /**
     * Get numeric role level for comparison
     */
    private static int getRoleLevel(Roles role) {
        return switch (role) {
            case SUPER_ADMIN -> 4;
            case ADMIN -> 3;
            case MANAGER -> 2;
            case USER -> 1;
        };
    }
}
