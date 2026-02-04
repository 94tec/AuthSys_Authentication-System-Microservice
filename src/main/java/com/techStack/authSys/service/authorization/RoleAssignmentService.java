package com.techStack.authSys.service.authorization;

import com.techStack.authSys.dto.internal.SecurityContext;
import com.techStack.authSys.models.user.ApprovalLevel;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.service.firebase.FirebaseClaimsService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.user.AdminNotificationService;
import com.techStack.authSys.util.validation.ValidationUtils;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
 * Uses ApprovalLevel enum for consistent approval hierarchy.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RoleAssignmentService {

    /* =========================
       Dependencies
       ========================= */

    private final AuditLogService auditLogService;
    private final PermissionProvider permissionProvider;
    private final FirebaseClaimsService firebaseClaimsService;
    private final AdminNotificationService notificationService;
    private final Clock clock;

    /* =========================
       Registration Rules
       ========================= */

    private final Map<Roles, RegistrationRule> roleRegistrationRules = new ConcurrentHashMap<>();

    @PostConstruct
    public void initializeRegistrationRules() {
        Instant now = clock.instant();

        // Map roles to their required approval levels
        roleRegistrationRules.put(
                Roles.SUPER_ADMIN,
                new RegistrationRule(
                        false,  // Cannot self-register
                        true,   // Requires approval
                        ApprovalLevel.PENDING_L2  // Highest level approval
                )
        );

        roleRegistrationRules.put(
                Roles.ADMIN,
                new RegistrationRule(
                        false,  // Cannot self-register
                        true,   // Requires approval
                        ApprovalLevel.PENDING_L2  // Highest level approval
                )
        );

        roleRegistrationRules.put(
                Roles.MANAGER,
                new RegistrationRule(
                        true,   // Can self-register
                        true,   // Requires approval
                        ApprovalLevel.PENDING_L1  // Standard approval
                )
        );

        roleRegistrationRules.put(
                Roles.USER,
                new RegistrationRule(
                        true,   // Can self-register
                        true,   // Requires approval
                        ApprovalLevel.PENDING_L1  // Standard approval
                )
        );

        log.info("✅ Registration rules initialized at {}", now);
        roleRegistrationRules.forEach((role, rule) ->
                log.debug("  - {}: Self-Reg={}, Approval={}, Level={}",
                        role, rule.allowSelfRegistration(), rule.requiresApproval(),
                        rule.getApprovalLevel())
        );
    }

    /* =========================
       PURE Registration Processing
       ========================= */

    /**
     * Evaluate registration request (NO Firebase, NO external I/O).
     * Pure domain logic - sets status and roles on User object.
     */
    public Mono<User> evaluateRegistration(
            User user,
            Set<Roles> requestedRoles,
            String ipAddress
    ) {
        Instant now = clock.instant();

        log.info("Evaluating registration for {} with roles {} at {}",
                user.getEmail(), requestedRoles, now);

        auditLogService.logRegistrationAttempt(user.getEmail(), requestedRoles, ipAddress);

        return validateSelfRegistration(user, requestedRoles)
                .flatMap(valid -> {
                    if (!valid) {
                        auditLogService.logRegistrationFailure(
                                user.getEmail(), "Self-registration not allowed", ipAddress);
                        return Mono.error(new SecurityException(
                                "Self-registration not allowed for role(s): " + requestedRoles));
                    }

                    return applyRolesAndApproval(user, requestedRoles, now, ipAddress);
                });
    }

    /**
     * Apply roles and approval workflow (PURE logic).
     * Modifies User object in-place, returns it for chaining.
     */
    private Mono<User> applyRolesAndApproval(
            User user,
            Set<Roles> roles,
            Instant now,
            String ipAddress
    ) {
        List<Roles> roleList = new ArrayList<>(roles);

        // Determine the highest approval level required
        ApprovalLevel approvalLevel = determineApprovalLevel(roleList);

        // Check if any role requires approval
        boolean requiresApproval = roleList.stream()
                .anyMatch(r -> {
                    RegistrationRule rule = roleRegistrationRules.get(r);
                    return rule != null && rule.requiresApproval();
                });

        // Set user status based on approval requirements
        if (requiresApproval) {
            user.setStatus(UserStatus.PENDING_APPROVAL);
            user.setEnabled(false);
            user.setApprovalLevel(approvalLevel);

            log.info("⏳ User {} requires {} approval for roles {} at {}",
                    user.getEmail(), approvalLevel.getDisplayName(), roleList, now);
        } else {
            user.setStatus(UserStatus.ACTIVE);
            user.setEnabled(true);
            user.setApprovalLevel(ApprovalLevel.NOT_REQUIRED);

            log.info("✅ User {} auto-approved for roles {} at {}",
                    user.getEmail(), roleList, now);
        }

        // Add roles to user
        roleList.forEach(user::addRole);

        // Audit log
        auditLogService.logRegistrationSuccess(
                user.getEmail(),
                new HashSet<>(roleList),
                user.getStatus(),
                ipAddress
        );

        return Mono.just(user);
    }

    /* =========================
       Role & Permission Assignment (I/O)
       ========================= */

    /**
     * Assign roles and permissions to user (requires UID from Firebase).
     * This is called AFTER Firebase user creation.
     */
    public Mono<User> assignRolesAndPermissions(User user, Instant now) {
        if (user.getId() == null || user.getId().isEmpty()) {
            return Mono.error(new IllegalStateException(
                    "Cannot assign roles - user has no Firebase UID"));
        }

        log.info("Assigning roles and permissions to user {} at {}", user.getEmail(), now);

        // Get roles from user (already set by evaluateRegistration)
        Set<Roles> roles = user.getRoles();

        if (roles == null || roles.isEmpty()) {
            log.warn("No roles to assign for user {} at {}", user.getEmail(), now);
            return Mono.just(user);
        }

        // Assign each role with its permissions
        return Flux.fromIterable(roles)
                .flatMap(role -> assignSingleRoleWithPermissions(user, role, now))
                .then(resolveAndSetEffectivePermissions(user, now))
                .thenReturn(user);
    }

    /**
     * Assign a single role with its permissions
     */
    private Mono<Void> assignSingleRoleWithPermissions(User user, Roles role, Instant now) {
        return permissionProvider.assignRole(user.getId(), role)
                .then(Mono.fromRunnable(() -> {
                    // Add ABAC attributes
                    addDefaultAttributes(user, role, now);
                }))
                .then(firebaseClaimsService.setClaimsReactive(user.getId(), role))
                .doOnSuccess(v -> {
                    Set<String> rolePermissions = permissionProvider.getPermissionsForRole(role)
                            .stream()
                            .map(Enum::name)
                            .collect(Collectors.toSet());

                    log.info("🔐 Role {} assigned with {} permissions to user {} at {}",
                            role, rolePermissions.size(), user.getId(), now);

                    auditLogService.logRoleAssignment(user.getId(), role.name(), "SYSTEM");
                })
                .onErrorResume(e -> {
                    log.error("❌ Error assigning role {} to user {} at {}: {}",
                            role, user.getId(), now, e.getMessage());
                    auditLogService.logRoleAssignmentFailure(user.getId(), role.name(), e.getMessage());
                    return Mono.error(new RuntimeException("Role assignment failed: " + e.getMessage()));
                });
    }

    /**
     * Resolve and set effective permissions on user object
     */
    private Mono<User> resolveAndSetEffectivePermissions(User user, Instant now) {
        return Mono.fromCallable(() -> {
            Set<String> effectivePermissions = permissionProvider.resolveEffectivePermissions(user);
            user.setAdditionalPermissions(new ArrayList<>(effectivePermissions));

            log.info("📋 Resolved {} effective permissions for user {} at {}",
                    effectivePermissions.size(), user.getEmail(), now);

            return user;
        });
    }

    /**
     * Add default ABAC attributes for role
     */
    private void addDefaultAttributes(User user, Roles role, Instant now) {
        String userId = user.getId();

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
       Approval Notifications
       ========================= */

    /**
     * Send approval notification to admins (call after user creation)
     */
    public Mono<Void> sendApprovalNotification(User user) {
        if (user.getStatus() != UserStatus.PENDING_APPROVAL) {
            return Mono.empty();
        }

        ApprovalLevel approvalLevel = user.getApprovalLevel();

        return notificationService.notifyAdminsForApproval(user, approvalLevel)
                .doOnSuccess(v -> log.info("📧 Approval notification sent for user {} at {}",
                        user.getEmail(), clock.instant()))
                .doOnError(e -> log.warn("Failed to send approval notification for {}: {}",
                        user.getEmail(), e.getMessage()))
                .onErrorResume(e -> Mono.empty()); // Non-blocking
    }

    /* =========================
       Validation Helpers
       ========================= */

    /**
     * Validate self-registration permission
     */
    private Mono<Boolean> validateSelfRegistration(User user, Set<Roles> requestedRoles) {
        return Mono.fromCallable(() -> {
            if (requestedRoles == null || requestedRoles.isEmpty()) {
                log.warn("⚠️ No roles requested by user {}", user.getEmail());
                return false;
            }

            for (Roles role : requestedRoles) {
                RegistrationRule rule = roleRegistrationRules.get(role);

                if (rule == null) {
                    log.error("❌ Unknown role [{}] requested by {}", role, user.getEmail());
                    return false;
                }

                if (!rule.allowSelfRegistration()) {
                    log.warn("🚫 Role [{}] does NOT allow self-registration (requested by {})",
                            role, user.getEmail());
                    return false;
                }
            }

            log.info("✅ Self-registration validation passed for user {} with roles {}",
                    user.getEmail(), requestedRoles);
            return true;
        });
    }

    /**
     * Determine highest approval level required for roles
     */
    private ApprovalLevel determineApprovalLevel(List<Roles> roles) {
        ApprovalLevel highestLevel = ApprovalLevel.PENDING_L1;

        for (Roles role : roles) {
            RegistrationRule rule = roleRegistrationRules.get(role);
            if (rule != null) {
                ApprovalLevel ruleLevel = rule.getApprovalLevel();
                // Compare order values to find highest level
                if (ruleLevel.getOrder() > highestLevel.getOrder()) {
                    highestLevel = ruleLevel;
                }
            }
        }

        return highestLevel;
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

        boolean canApprove = canApproveAtLevel(requesterRole, requiredLevel);

        log.debug("🔐 Approval check - Requester: {} ({}), Target: {}, Required: {}, Result: {}",
                securityContext.getRequesterEmail(), requesterRole,
                targetUser.getEmail(), requiredLevel.getDisplayName(), canApprove);

        return canApprove;
    }

    /**
     * Check if role can approve at specific level
     */
    private boolean canApproveAtLevel(Roles requesterRole, ApprovalLevel requiredLevel) {
        if (requesterRole == null || requiredLevel == null) {
            return false;
        }

        // Map approval levels to role requirements
        return switch (requiredLevel) {
            case PENDING_L1 ->
                    requesterRole == Roles.MANAGER ||
                            requesterRole == Roles.ADMIN ||
                            requesterRole == Roles.SUPER_ADMIN;

            case PENDING_L2 ->
                    requesterRole == Roles.ADMIN ||
                            requesterRole == Roles.SUPER_ADMIN;

            case NOT_REQUIRED, APPROVED_L1, APPROVED, REJECTED ->
                    false; // Terminal states don't need approval
        };
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
        private final ApprovalLevel approvalLevel;

        public RegistrationRule(
                boolean allowSelfRegistration,
                boolean requiresApproval,
                ApprovalLevel approvalLevel
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
}