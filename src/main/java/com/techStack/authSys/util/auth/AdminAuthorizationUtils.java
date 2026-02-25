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
     * Check if performer can manage target user.
     *
     * Rules:
     *   - SUPER_ADMIN can manage everyone
     *   - ADMIN can manage USER and MANAGER only
     *   - ADMIN cannot manage ADMIN or SUPER_ADMIN
     */
    public static Mono<Boolean> checkManagementAuthority(User targetUser, Roles performerRole) {
        return Mono.fromCallable(() -> {
            if (performerRole == Roles.SUPER_ADMIN) {
                return true;
            }

            if (performerRole == Roles.ADMIN) {
                Set<Roles> targetRoles = targetUser.getRoles();
                boolean targetIsAdmin = targetRoles.contains(Roles.ADMIN)
                        || targetRoles.contains(Roles.SUPER_ADMIN);
                return !targetIsAdmin;
            }

            return false;
        });
    }

    /**
     * Check if performer can view target user.
     */
    public static boolean canViewUser(User targetUser, Roles performerRole) {
        if (performerRole == Roles.SUPER_ADMIN) {
            return true;
        }

        if (performerRole == Roles.ADMIN) {
            Set<Roles> targetRoles = targetUser.getRoles();
            return !targetRoles.contains(Roles.ADMIN)
                    && !targetRoles.contains(Roles.SUPER_ADMIN);
        }

        return false;
    }

    /**
     * Check role hierarchy.
     *
     * @return true if performerRole has equal or higher level than requiredRole
     */
    public static boolean hasRoleLevel(Roles performerRole, Roles requiredRole) {
        return performerRole.getLevel() >= requiredRole.getLevel();
    }
}