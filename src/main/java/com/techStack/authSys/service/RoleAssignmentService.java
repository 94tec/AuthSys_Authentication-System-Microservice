package com.techStack.authSys.service;

import com.google.firebase.auth.FirebaseAuth;
import com.techStack.authSys.dto.SecurityContext;
import com.techStack.authSys.models.Permissions;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.PermissionProvider;
import com.techStack.authSys.util.ValidationUtils;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static com.techStack.authSys.models.Roles.MANAGER;
import static com.techStack.authSys.models.Roles.USER;

@Service
public class RoleAssignmentService {
    private static final Logger logger = LoggerFactory.getLogger(RoleAssignmentService.class);
    private final FirebaseAuth firebaseAuth;
    private final AuditLogService auditLogService;
    private final PermissionProvider permissionProvider;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final FirebaseClaimsService firebaseClaimsService;
    private  final AdminNotificationService notificationService;

    // Defines registration rules for each role
    private final Map<Roles, RegistrationRule> roleRegistrationRules = new ConcurrentHashMap<>();

    public RoleAssignmentService(FirebaseAuth firebaseAuth, AuditLogService auditLogService, PermissionProvider permissionProvider,
                                 FirebaseServiceAuth firebaseServiceAuth,
                                 FirebaseClaimsService firebaseClaimsService, AdminNotificationService notificationService) {
        this.firebaseAuth = firebaseAuth;
        this.auditLogService = auditLogService;
        this.permissionProvider = permissionProvider;
        this.firebaseServiceAuth = firebaseServiceAuth;
        this.firebaseClaimsService = firebaseClaimsService;
        this.notificationService = notificationService;
        initializeRegistrationRules();
    }
    // Registration rules define:
    // 1. Can user self-register with this role?
    // 2. Does account need approval after registration?
    private void initializeRegistrationRules() {
        // Following document recommendations - ALL roles now require approval for security
        roleRegistrationRules.put(
                Roles.SUPER_ADMIN,
                new RegistrationRule(false, true, ApprovalLevel.SUPER_ADMIN_ONLY)
        );

        roleRegistrationRules.put(
                Roles.ADMIN,
                new RegistrationRule(false, true, ApprovalLevel.SUPER_ADMIN_ONLY)
        );

        roleRegistrationRules.put(
                Roles.MANAGER,
                new RegistrationRule(true, true, ApprovalLevel.ADMIN_OR_SUPER_ADMIN)
        );

        roleRegistrationRules.put(
                Roles.USER,
                new RegistrationRule(true, true, ApprovalLevel.MANAGER_OR_ABOVE)
        );

        logger.info("✅ Registration rules initialized:");
        roleRegistrationRules.forEach((role, rule) ->
                logger.info("  - {}: Self-Reg={}, Approval={}, Level={}",
                        role, rule.allowSelfRegistration(), rule.requiresApproval(), rule.getApprovalLevel())
        );
    }
    /**
     * Main registration processing - Enhanced with security validations
     */
    public Mono<User> processUserRegistration(
            User user,
            Set<Roles> requestedRoles,
            String ipAddress,
            String deviceFingerprint) {

        // Audit log: Registration attempt
        auditLogService.logRegistrationAttempt(user.getEmail(), requestedRoles, ipAddress);

        return firebaseServiceAuth.findByEmail(user.getEmail())
                .flatMap(existingUser -> {
                    // User exists - validate role upgrade
                    logger.info("Existing user {} requesting role upgrade from {} to {}",
                            existingUser.getEmail(), existingUser.getRoles(), requestedRoles);

                    return validateRoleUpgrade(existingUser.getRoles(), requestedRoles)
                            .flatMap(valid -> {
                                if (!valid) {
                                    auditLogService.logRegistrationFailure(
                                            user.getEmail(), "Invalid role upgrade", ipAddress);
                                    return Mono.error(new SecurityException(
                                            "Invalid role upgrade request. Cannot upgrade from " +
                                                    existingUser.getRoles() + " to " + requestedRoles));
                                }
                                return processRolesForUser(user, requestedRoles, ipAddress, deviceFingerprint);
                            });
                })
                .switchIfEmpty(Mono.defer(() -> {
                    // New user - validate self-registration permission
                    logger.info("New user registration: {} with roles {}", user.getEmail(), requestedRoles);

                    return validateSelfRegistration(user, requestedRoles)
                            .flatMap(valid -> {
                                if (!valid) {
                                    auditLogService.logRegistrationFailure(
                                            user.getEmail(), "Self-registration not allowed", ipAddress);
                                    return Mono.error(new SecurityException(
                                            "Self-registration not allowed for requested role(s): " + requestedRoles));
                                }
                                return processRolesForUser(user, requestedRoles, ipAddress, deviceFingerprint);
                            });
                }));
    }
    /**
     * Validate if user can self-register with requested roles
     * Enforces: roleRegistrationRules.get(role).allowSelfRegistration()
     */
    private Mono<Boolean> validateSelfRegistration(User user, Set<Roles> requestedRoles) {
        return Mono.fromCallable(() -> {
            if (requestedRoles == null || requestedRoles.isEmpty()) {
                logger.warn("⚠️ No roles requested by user {}", user.getEmail());
                return false;
            }

            // Check each requested role
            for (Roles role : requestedRoles) {
                RegistrationRule rule = roleRegistrationRules.get(role);

                if (rule == null) {
                    logger.error("❌ Unknown role [{}] requested by {}", role, user.getEmail());
                    return false;
                }

                // CRITICAL CHECK: Can user self-register with this role?
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
     * Process roles for user - Assign roles, permissions, determine approval status
     * Enhanced with Fine-Grained Authorization (FGA) principles
     */
    private Mono<User> processRolesForUser(
            User user,
            Set<Roles> requestedRoles,
            String ipAddress,
            String deviceFingerprint) {

        List<Roles> roleList = new ArrayList<>(requestedRoles);

        // Determine most restrictive approval requirement
        ApprovalLevel requiredApprovalLevel = determineApprovalLevel(roleList);
        boolean requiresApproval = roleList.stream()
                .anyMatch(role -> {
                    RegistrationRule rule = roleRegistrationRules.get(role);
                    return rule != null && rule.requiresApproval();
                });

        // Set user status based on approval requirement
        if (requiresApproval) {
            user.setStatus(User.Status.PENDING_APPROVAL);
            user.setEnabled(false);
            user.setApprovalLevel(ApprovalLevel.valueOf(requiredApprovalLevel.name()));

            logger.info("⏳ User {} requires {} approval for roles {}",
                    user.getEmail(), requiredApprovalLevel, roleList);
        } else {
            user.setStatus(User.Status.ACTIVE);
            user.setEnabled(true);

            logger.info("✅ User {} auto-approved for roles {}", user.getEmail(), roleList);
        }

        // Assign all requested roles and their permissions
        return Flux.fromIterable(roleList)
                .flatMap(role -> assignRoleAndPermissions(user, role))
                .then(Mono.fromCallable(() -> {
                    // Apply Fine-Grained Authorization (FGA)
                    // Resolve effective permissions considering:
                    // - Role-based permissions (RBAC)
                    // - User attributes (ABAC)
                    // - Resource-specific rules
                    Set<String> effectivePermissions = permissionProvider.resolveEffectivePermissions(user);
                    user.setPermissions(new ArrayList<>(effectivePermissions));

                    logger.info("📋 Resolved {} effective permissions for user {} (Status: {})",
                            effectivePermissions.size(), user.getEmail(), user.getStatus());

                    return user;
                }))
                .flatMap(u -> {
                    // If approval required, notify admins
                    if (requiresApproval) {
                        return notificationService.notifyAdminsForApproval(u, requiredApprovalLevel)
                                .doOnSuccess(v -> logger.info("📧 Approval notification sent for user {}", u.getEmail()))
                                .thenReturn(u);
                    }
                    return Mono.just(u);
                })
                .doOnSuccess(u -> {
                    // Audit log: Registration successful
                    auditLogService.logRegistrationSuccess(
                            u.getEmail(), u.getRoles(), u.getStatus().name(), ipAddress);
                });
    }

    /**
     * Determine the required approval level based on requested roles
     */
    private ApprovalLevel determineApprovalLevel(List<Roles> roles) {
        ApprovalLevel highestLevel = ApprovalLevel.MANAGER_OR_ABOVE;

        for (Roles role : roles) {
            RegistrationRule rule = roleRegistrationRules.get(role);
            if (rule != null && rule.getApprovalLevel().ordinal() > highestLevel.ordinal()) {
                highestLevel = rule.getApprovalLevel();
            }
        }

        return highestLevel;
    }
    /**
     * Assign a single role and its permissions
     * Implements Fine-Grained Authorization (FGA) at role level
     */
    public Mono<User> assignRoleAndPermissions(User user, Roles role) {
        user.addRole(role);

        return permissionProvider.assignRole(user.getId(), role)
                .then(Mono.fromRunnable(() -> {
                    // Add default attributes for ABAC (Attribute-Based Access Control)
                    addDefaultAttributes(user, role);
                }))
                .then(Mono.fromCallable(() -> {
                    // Log permission assignment for audit trail
                    Set<String> rolePermissions = permissionProvider.getPermissionsForRole(role)
                            .stream()
                            .map(p -> p.getName())
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
     * Add default user attributes for Fine-Grained Authorization (ABAC)
     */
    private void addDefaultAttributes(User user, Roles role) {
        String userId = user.getId();

        // Department-based access control
        if (user.getDepartment() != null && !user.getDepartment().isEmpty()) {
            permissionProvider.addUserAttribute(userId, "department", user.getDepartment(), "system");
        }

        // Access level based on role
        switch (role) {
            case SUPER_ADMIN -> {
                permissionProvider.addUserAttribute(userId, "access_level", "super_admin", "system");
                permissionProvider.addUserAttribute(userId, "can_approve", "all", "system");
            }
            case ADMIN -> {
                permissionProvider.addUserAttribute(userId, "access_level", "admin", "system");
                permissionProvider.addUserAttribute(userId, "can_approve", "manager,user", "system");
            }
            case MANAGER -> {
                permissionProvider.addUserAttribute(userId, "access_level", "manager", "system");
                permissionProvider.addUserAttribute(userId, "can_approve", "user", "system");
            }
            case USER -> {
                permissionProvider.addUserAttribute(userId, "access_level", "standard", "system");
            }
        }

        // Add registration context attributes
        permissionProvider.addUserAttribute(userId, "registration_date", Instant.now().toString(), "system");
        permissionProvider.addUserAttribute(userId, "requires_approval",
                String.valueOf(user.getStatus() == User.Status.PENDING_APPROVAL), "system");
    }
    /**
     * Determines if current user can approve the target user
     */
    public boolean canApproveUser(SecurityContext securityContext, User targetUser) {
        ValidationUtils.validateNotNull(securityContext, "Security context cannot be null");
        ValidationUtils.validateNotNull(targetUser, "Target user cannot be null");

        Roles requesterRole = securityContext.getRequesterRole();
        ApprovalLevel requiredApprovalLevel = targetUser.getApprovalLevel()
                .orElse(ApprovalLevel.MANAGER_OR_ABOVE);

        boolean canApprove = canApproveAtLevel(requesterRole, requiredApprovalLevel);

        logger.debug("🔐 Approval check - Requester: {} ({}), Target: {}, Required Level: {}, Result: {}",
                securityContext.getRequesterEmail(), requesterRole,
                targetUser.getEmail(), requiredApprovalLevel, canApprove);

        return canApprove;
    }

    /**
     * Determines if the given requester role is allowed to approve actions requiring a certain approval level.
     */
    private boolean canApproveAtLevel(Roles requesterRole, ApprovalLevel requiredApprovalLevel) {
        if (requesterRole == null || requiredApprovalLevel == null) {
            logger.warn("⚠️ Missing role or approval level in canApproveAtLevel()");
            return false;
        }

        switch (requiredApprovalLevel) {
            case MANAGER_OR_ABOVE:
                return requesterRole == Roles.MANAGER || requesterRole == Roles.SUPER_ADMIN;

            case SUPER_ADMIN_ONLY:
                return requesterRole == Roles.SUPER_ADMIN;

            default:
                logger.warn("⚠️ Unknown approval level: {}", requiredApprovalLevel);
                return false;
        }
    }

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
            return true;  // All roles can be upgraded
        });
    }

    private Mono<Boolean> validateRoleAssignment(User user, Set<Roles> requestedRoles) {
        return Mono.fromCallable(() -> {
            if (requestedRoles == null || requestedRoles.isEmpty()) {
                logger.warn("No roles requested by user {}", user.getEmail());
                return false;
            }

            Set<Roles> allowedRoles = getAllowedRolesForUser(user);
            Set<Roles> invalidRoles = requestedRoles.stream()
                    .filter(role -> !allowedRoles.contains(role))
                    .collect(Collectors.toSet());

            if (!invalidRoles.isEmpty()) {
                logger.warn("🚫 Invalid roles requested by [{}]: {}. Allowed roles: {}",
                        user.getEmail(), invalidRoles, allowedRoles);
                return false;
            }

            for (Roles role : requestedRoles) {
                RegistrationRule rule = roleRegistrationRules.get(role);
                if (rule == null) {
                    logger.warn("Non-existent role [{}] requested by {}", role, user.getEmail());
                    return false;
                }
                if (!rule.allowSelfRegistration()) {
                    logger.warn("⚠️ Role [{}] not allowed for self-registration by {}", role, user.getEmail());
                    return false;
                }
            }

            return true;
        });
    }

    private Set<Roles> getAllowedRolesForUser(User user) {
        return roleRegistrationRules.entrySet().stream()
                .filter(entry -> entry.getValue().allowSelfRegistration())
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    public Mono<User> approveRoleRequest(String userId) {
        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != User.Status.PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException("User is not pending approval"));
                    }
                    if (user.getRoles() == null || user.getRoles().isEmpty()) {
                        return Mono.error(new IllegalStateException("No role requested for approval"));
                    }

                    // Iterate over the Set of Roles and assign each role and permissions
                    return Flux.fromIterable(user.getRoles())
                            .flatMap(role -> assignRoleAndPermissions(user, role))
                            .then(Mono.just(user)); // Return the updated user after processing all roles
                });
    }
    /**
     * Enhanced Registration Rule with approval level
     */
    private static class RegistrationRule {
        private final boolean allowSelfRegistration;
        private final boolean requiresApproval;
        @Getter
        private final RoleAssignmentService.ApprovalLevel approvalLevel;

        public RegistrationRule(boolean allowSelfRegistration, boolean requiresApproval, RoleAssignmentService.ApprovalLevel approvalLevel) {
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
     * Approval level hierarchy - Who can approve which roles
     */
    public enum ApprovalLevel {
        MANAGER_OR_ABOVE,        // USER registrations
        ADMIN_OR_SUPER_ADMIN,    // MANAGER registrations
        SUPER_ADMIN_ONLY         // ADMIN/SUPER_ADMIN registrations
    }

    public Roles extractHighestRole(Authentication authentication) {
        Set<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        // Check in order of privilege
        if (authorities.contains("ROLE_SUPER_ADMIN")) {
            return Roles.SUPER_ADMIN;
        } else if (authorities.contains("ROLE_ADMIN")) {
            return Roles.ADMIN;
        } else if (authorities.contains("ROLE_MANAGER")) {
            return Roles.MANAGER;
        } else {
            return Roles.USER;
        }
    }
}