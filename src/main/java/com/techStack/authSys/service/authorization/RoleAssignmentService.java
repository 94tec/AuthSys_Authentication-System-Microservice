package com.techStack.authSys.service.authorization;

import com.google.firebase.auth.FirebaseAuth;
import com.techStack.authSys.dto.internal.SecurityContext;
import com.techStack.authSys.models.user.ApprovalLevel;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.firebase.FirebaseClaimsService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.user.AdminNotificationService;
import com.techStack.authSys.util.validation.ValidationUtils;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Role Assignment Service
 *
 * Manages role assignment, validation, and approval workflows.
 * Implements Fine-Grained Authorization (FGA) with registration rules.
 */
@Service
@RequiredArgsConstructor
public class RoleAssignmentService {

    private static final Logger logger = LoggerFactory.getLogger(RoleAssignmentService.class);

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseAuth firebaseAuth;
    private final AuditLogService auditLogService;
    private final PermissionProvider permissionProvider;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final FirebaseClaimsService firebaseClaimsService;
    private final AdminNotificationService notificationService;
    private final Clock clock;

    /* =========================
       Registration Rules
       ========================= */

    private final Map<Roles, RegistrationRule> roleRegistrationRules = new ConcurrentHashMap<>();

    @PostConstruct
    public void initializeRegistrationRules() {
        // SUPER_ADMIN: Cannot self-register, requires super admin approval
        roleRegistrationRules.put(
                Roles.SUPER_ADMIN,
                new RegistrationRule(false, true, RoleApprovalLevel.SUPER_ADMIN_ONLY)
        );

        // ADMIN: Cannot self-register, requires super admin approval
        roleRegistrationRules.put(
                Roles.ADMIN,
                new RegistrationRule(false, true, RoleApprovalLevel.SUPER_ADMIN_ONLY)
        );

        // MANAGER: Can self-register, requires admin/super admin approval
        roleRegistrationRules.put(
                Roles.MANAGER,
                new RegistrationRule(true, true, RoleApprovalLevel.ADMIN_OR_SUPER_ADMIN)
        );

        // USER: Can self-register, requires manager/admin/super admin approval
        roleRegistrationRules.put(
                Roles.USER,
                new RegistrationRule(true, true, RoleApprovalLevel.MANAGER_OR_ABOVE)
        );

        logger.info("✅ Registration rules initialized:");
        roleRegistrationRules.forEach((role, rule) ->
                logger.info("  - {}: Self-Reg={}, Approval={}, Level={}",
                        role, rule.allowSelfRegistration(), rule.requiresApproval(), rule.getApprovalLevel())
        );
    }

    /* =========================
       Registration Processing
       ========================= */

    /**
     * Process user registration with role validation and assignment
     */
    public Mono<User> processUserRegistration(
            User user,
            Set<Roles> requestedRoles,
            String ipAddress,
            String deviceFingerprint
    ) {
        Instant now = clock.instant();

        // Audit log: Registration attempt
        auditLogService.logRegistrationAttempt(user.getEmail(), requestedRoles, ipAddress);

        return firebaseServiceAuth.findByEmail(user.getEmail())
                .flatMap(existingUser -> {
                    // Existing user - validate role upgrade
                    logger.info("Existing user {} requesting role upgrade from {} to {}",
                            existingUser.getEmail(), existingUser.getRoles(), requestedRoles);

                    return validateRoleUpgrade(existingUser.getRoles(), requestedRoles)
                            .flatMap(valid -> {
                                if (!valid) {
                                    auditLogService.logRegistrationFailure(
                                            user.getEmail(), "Invalid role upgrade", ipAddress);
                                    return Mono.error(new SecurityException(
                                            "Invalid role upgrade request from " +
                                                    existingUser.getRoles() + " to " + requestedRoles));
                                }
                                return processRolesForUser(user, requestedRoles, ipAddress, now);
                            });
                })
                .switchIfEmpty(Mono.defer(() -> {
                    // New user - validate self-registration
                    logger.info("New user registration: {} with roles {}",
                            user.getEmail(), requestedRoles);

                    return validateSelfRegistration(user, requestedRoles)
                            .flatMap(valid -> {
                                if (!valid) {
                                    auditLogService.logRegistrationFailure(
                                            user.getEmail(), "Self-registration not allowed", ipAddress);
                                    return Mono.error(new SecurityException(
                                            "Self-registration not allowed for role(s): " + requestedRoles));
                                }
                                return processRolesForUser(user, requestedRoles, ipAddress, now);
                            });
                }));
    }

    /**
     * Validate self-registration permission
     */
    private Mono<Boolean> validateSelfRegistration(User user, Set<Roles> requestedRoles) {
        return Mono.fromCallable(() -> {
            if (requestedRoles == null || requestedRoles.isEmpty()) {
                logger.warn("⚠️ No roles requested by user {}", user.getEmail());
                return false;
            }

            for (Roles role : requestedRoles) {
                RegistrationRule rule = roleRegistrationRules.get(role);

                if (rule == null) {
                    logger.error("❌ Unknown role [{}] requested by {}", role, user.getEmail());
                    return false;
                }

                if (!rule.allowSelfRegistration()) {
                    logger.warn("🚫 Role [{}] does NOT allow self-registration (requested by {})",
                            role, user.getEmail());
                    return false;
                }
            }

            logger.info("✅ Self-registration validation passed for user {} with roles {}",
                    user.getEmail(), requestedRoles);
            return true;
        });
    }

    /**
     * Process roles for user with approval workflow
     */
    private Mono<User> processRolesForUser(
            User user,
            Set<Roles> requestedRoles,
            String ipAddress,
            Instant now
    ) {
        List<Roles> roleList = new ArrayList<>(requestedRoles);

        // Determine approval requirements
        RoleApprovalLevel requiredApprovalLevel = determineApprovalLevel(roleList);
        boolean requiresApproval = roleList.stream()
                .anyMatch(role -> {
                    RegistrationRule rule = roleRegistrationRules.get(role);
                    return rule != null && rule.requiresApproval();
                });

        // Set user status
        if (requiresApproval) {
            user.setStatus(UserStatus.PENDING_APPROVAL);
            user.setEnabled(false);
            user.setApprovalLevel(ApprovalLevel.valueOf(requiredApprovalLevel.name()));

            logger.info("⏳ User {} requires {} approval for roles {}",
                    user.getEmail(), requiredApprovalLevel, roleList);
        } else {
            user.setStatus(UserStatus.ACTIVE);
            user.setEnabled(true);

            logger.info("✅ User {} auto-approved for roles {}", user.getEmail(), roleList);
        }

        // Assign roles and permissions
        return Flux.fromIterable(roleList)
                .flatMap(role -> assignRoleAndPermissions(user, role, now))
                .then(Mono.fromCallable(() -> {
                    // Resolve effective permissions
                    Set<String> effectivePermissions =
                            permissionProvider.resolveEffectivePermissions(user);
                    user.setAdditionalPermissions(new ArrayList<>(effectivePermissions));

                    logger.info("📋 Resolved {} effective permissions for user {} (Status: {})",
                            effectivePermissions.size(), user.getEmail(), user.getStatus());

                    return user;
                }))
                .flatMap(u -> {
                    // Send approval notification if needed
                    if (requiresApproval) {
                        return notificationService.notifyAdminsForApproval(u, requiredApprovalLevel)
                                .doOnSuccess(v -> logger.info("📧 Approval notification sent for user {}",
                                        u.getEmail()))
                                .thenReturn(u);
                    }
                    return Mono.just(u);
                })
                .doOnSuccess(u -> {
                    auditLogService.logRegistrationSuccess(
                            u.getEmail(),
                            u.getRoles().stream().map(Enum::name).collect(Collectors.toSet()),
                            u.getStatus().name(),
                            ipAddress
                    );
                });
    }

    /**
     * Determine required approval level
     */
    private RoleApprovalLevel determineApprovalLevel(List<Roles> roles) {
        RoleApprovalLevel highestLevel = RoleApprovalLevel.MANAGER_OR_ABOVE;

        for (Roles role : roles) {
            RegistrationRule rule = roleRegistrationRules.get(role);
            if (rule != null && rule.getApprovalLevel().ordinal() > highestLevel.ordinal()) {
                highestLevel = rule.getApprovalLevel();
            }
        }

        return highestLevel;
    }

    /**
     * Assign role and permissions to user
     */
    public Mono<User> assignRoleAndPermissions(User user, Roles role, Instant now) {
        user.addRole(role);

        return permissionProvider.assignRole(user.getId(), role)
                .then(Mono.fromRunnable(() -> {
                    // Add ABAC attributes
                    addDefaultAttributes(user, role);
                }))
                .then(Mono.fromCallable(() -> {
                    Set<String> rolePermissions = permissionProvider.getPermissionsForRole(role)
                            .stream()
                            .map(Enum::name)
                            .collect(Collectors.toSet());

                    logger.info("🔐 Role {} assigned with {} permissions to user {}",
                            role, rolePermissions.size(), user.getId());

                    return user;
                }))
                .flatMap(u -> firebaseClaimsService.setClaimsReactive(u.getId(), role).thenReturn(u))
                .doOnSuccess(u -> {
                    auditLogService.logRoleAssignment(u.getId(), role.name(), "SYSTEM");
                })
                .onErrorResume(e -> {
                    logger.error("❌ Error assigning role {} to user {}: {}",
                            role, user.getId(), e.getMessage());
                    auditLogService.logRoleAssignmentFailure(user.getId(), role.name(), e.getMessage());
                    return Mono.error(new RuntimeException("Role assignment failed: " + e.getMessage()));
                });
    }

    /**
     * Add default ABAC attributes
     */
    private void addDefaultAttributes(User user, Roles role) {
        String userId = user.getId();
        Instant now = clock.instant();

        // Department-based access
        if (user.getDepartment() != null && !user.getDepartment().isEmpty()) {
            permissionProvider.addUserAttribute(userId, "department", "name", user.getDepartment());
        }

        // Role-based attributes
        switch (role) {
            case SUPER_ADMIN -> {
                permissionProvider.addUserAttribute(userId, "access", "level", "super_admin");
                permissionProvider.addUserAttribute(userId, "approval", "can_approve", "all");
            }
            case ADMIN -> {
                permissionProvider.addUserAttribute(userId, "access", "level", "admin");
                permissionProvider.addUserAttribute(userId, "approval", "can_approve", "manager,user");
            }
            case MANAGER -> {
                permissionProvider.addUserAttribute(userId, "access", "level", "manager");
                permissionProvider.addUserAttribute(userId, "approval", "can_approve", "user");
            }
            case USER -> {
                permissionProvider.addUserAttribute(userId, "access", "level", "standard");
            }
        }

        // Registration metadata
        permissionProvider.addUserAttribute(userId, "registration", "date", now.toString());
        permissionProvider.addUserAttribute(userId, "registration", "requires_approval",
                String.valueOf(user.getStatus() == UserStatus.PENDING_APPROVAL));
    }

    /* =========================
       Approval Validation
       ========================= */

    /**
     * Check if requester can approve target user
     */
    public boolean canApproveUser(SecurityContext securityContext, User targetUser) {
        ValidationUtils.validateNotNull(securityContext, "Security context cannot be null");
        ValidationUtils.validateNotNull(targetUser, "Target user cannot be null");

        Roles requesterRole = securityContext.getRequesterRole();
        ApprovalLevel requiredLevel = targetUser.getApprovalLevel();

        boolean canApprove = canApproveAtLevel(requesterRole,
                RoleApprovalLevel.valueOf(requiredLevel.name()));

        logger.debug("🔐 Approval check - Requester: {} ({}), Target: {}, Required: {}, Result: {}",
                securityContext.getRequesterEmail(), requesterRole,
                targetUser.getEmail(), requiredLevel, canApprove);

        return canApprove;
    }

    private boolean canApproveAtLevel(Roles requesterRole, RoleApprovalLevel requiredLevel) {
        if (requesterRole == null || requiredLevel == null) {
            return false;
        }

        return switch (requiredLevel) {
            case MANAGER_OR_ABOVE ->
                    requesterRole == Roles.MANAGER ||
                            requesterRole == Roles.ADMIN ||
                            requesterRole == Roles.SUPER_ADMIN;
            case ADMIN_OR_SUPER_ADMIN ->
                    requesterRole == Roles.ADMIN ||
                            requesterRole == Roles.SUPER_ADMIN;
            case SUPER_ADMIN_ONLY ->
                    requesterRole == Roles.SUPER_ADMIN;
        };
    }

    /**
     * Validate role upgrade request
     */
    private Mono<Boolean> validateRoleUpgrade(Set<Roles> currentRoles, Set<Roles> requestedRoles) {
        return Mono.fromCallable(() -> {
            for (Roles requestedRole : requestedRoles) {
                for (Roles currentRole : currentRoles) {
                    if (!requestedRole.hasHigherPrivilegesThan(currentRole) ||
                            !currentRole.canRequestUpgradeTo(requestedRole)) {
                        return false;
                    }
                }
            }
            return true;
        });
    }

    /**
     * Extract highest role from authentication
     */
    public Roles extractHighestRole(Authentication authentication) {
        Set<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        if (authorities.contains("ROLE_SUPER_ADMIN")) return Roles.SUPER_ADMIN;
        if (authorities.contains("ROLE_ADMIN")) return Roles.ADMIN;
        if (authorities.contains("ROLE_MANAGER")) return Roles.MANAGER;
        return Roles.USER;
    }

    /* =========================
       Inner Classes
       ========================= */

    /**
     * Registration Rule Configuration
     */
    private static class RegistrationRule {
        private final boolean allowSelfRegistration;
        private final boolean requiresApproval;
        @Getter
        private final RoleApprovalLevel approvalLevel;

        public RegistrationRule(
                boolean allowSelfRegistration,
                boolean requiresApproval,
                RoleApprovalLevel approvalLevel
        ) {
            this.allowSelfRegistration = allowSelfRegistration;
            this.requiresApproval = requiresApproval;
            this.approvalLevel = approvalLevel;
        }

        public boolean allowSelfRegistration() {
            return allowSelfRegistration;
        }

        public boolean requiresApproval() {
            return requiresApproval;
        }
    }

    /**
     * Role Approval Level Hierarchy
     */
    public enum RoleApprovalLevel {
        MANAGER_OR_ABOVE,
        ADMIN_OR_SUPER_ADMIN,
        SUPER_ADMIN_ONLY
    }
}