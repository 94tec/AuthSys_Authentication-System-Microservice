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
import reactor.core.scheduler.Schedulers;

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
 *
 * Migration note:
 *   Updated to work with string-based permissions from PermissionService.
 *   getPermissionsForRole() now returns Set<String> (full names like
 *   "portfolio:view") instead of Set<Permissions> enum values.
 *   All downstream calls updated accordingly.
 *
 * Reactive threading:
 *   Pure domain logic (validateSelfRegistration, applyRolesAndApproval)
 *   runs synchronously and returns Mono.just() — no Mono.fromCallable()
 *   needed for CPU-only operations. I/O operations (Firestore, Firebase)
 *   are dispatched to Schedulers.boundedElastic() in the repository layer.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RoleAssignmentService {

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private final AuditLogService auditLogService;
    private final PermissionProvider permissionProvider;
    private final FirebaseClaimsService firebaseClaimsService;
    private final AdminNotificationService notificationService;
    private final Clock clock;

    // -------------------------------------------------------------------------
    // Registration rules
    // -------------------------------------------------------------------------

    private final Map<Roles, RegistrationRule> roleRegistrationRules = new ConcurrentHashMap<>();

    @PostConstruct
    public void initializeRegistrationRules() {
        Instant now = clock.instant();

        roleRegistrationRules.put(Roles.SUPER_ADMIN, new RegistrationRule(
                false,                   // cannot self-register
                true,                    // requires approval
                ApprovalLevel.PENDING_L2 // highest level approval
        ));

        roleRegistrationRules.put(Roles.ADMIN, new RegistrationRule(
                false,
                true,
                ApprovalLevel.PENDING_L2
        ));

        roleRegistrationRules.put(Roles.MANAGER, new RegistrationRule(
                true,                    // can self-register
                true,
                ApprovalLevel.PENDING_L1 // standard approval
        ));

        roleRegistrationRules.put(Roles.USER, new RegistrationRule(
                true,
                true,
                ApprovalLevel.PENDING_L1
        ));

        log.info("✅ Registration rules initialized at {}", now);
        roleRegistrationRules.forEach((role, rule) ->
                log.debug("  - {}: selfReg={}, approval={}, level={}",
                        role, rule.allowSelfRegistration(),
                        rule.requiresApproval(), rule.getApprovalLevel())
        );
    }

    // -------------------------------------------------------------------------
    // Pure registration processing (no I/O)
    // -------------------------------------------------------------------------

    /**
     * Evaluates a registration request and sets status/roles on the User object.
     *
     * Pure domain logic — no Firestore, no Firebase, no external I/O.
     * Called BEFORE Firebase user creation so it can fail fast without
     * leaving orphaned Firebase accounts.
     *
     * @param user           the user being registered (mutated in place)
     * @param requestedRoles the roles the user is requesting
     * @param ipAddress      the IP address for audit logging
     * @return Mono emitting the user with status and roles applied
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

        // validateSelfRegistration is pure CPU logic — no Mono.fromCallable needed
        boolean valid = isSelfRegistrationAllowed(user, requestedRoles);

        if (!valid) {
            auditLogService.logRegistrationFailure(
                    user.getEmail(), "Self-registration not allowed", ipAddress);
            return Mono.error(new SecurityException(
                    "Self-registration not allowed for role(s): " + requestedRoles));
        }

        return applyRolesAndApproval(user, requestedRoles, now, ipAddress);
    }

    /**
     * Applies roles and approval state to the user (pure domain logic).
     * Mutates the user object and returns it wrapped in Mono.just().
     */
    private Mono<User> applyRolesAndApproval(
            User user,
            Set<Roles> roles,
            Instant now,
            String ipAddress
    ) {
        List<Roles> roleList = new ArrayList<>(roles);

        ApprovalLevel approvalLevel   = determineApprovalLevel(roleList);
        boolean       requiresApproval = roleList.stream()
                .anyMatch(r -> {
                    RegistrationRule rule = roleRegistrationRules.get(r);
                    return rule != null && rule.requiresApproval();
                });

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

        roleList.forEach(user::addRole);

        auditLogService.logRegistrationSuccess(
                user.getEmail(),
                new HashSet<>(roleList),
                user.getStatus(),
                ipAddress
        );

        return Mono.just(user);
    }

    // -------------------------------------------------------------------------
    // Role and permission assignment (I/O — requires Firebase UID)
    // -------------------------------------------------------------------------

    /**
     * Assigns roles and permissions to a user in Firestore and Firebase.
     *
     * Must be called AFTER Firebase user creation so the UID is available.
     * Roles must already be set on the user object by evaluateRegistration().
     *
     * @param user the user entity with id (Firebase UID) set
     * @param now  the current instant for audit logging
     * @return Mono emitting the user with effective permissions populated
     */
    public Mono<User> assignRolesAndPermissions(User user, Instant now) {
        if (user.getId() == null || user.getId().isEmpty()) {
            return Mono.error(new IllegalStateException(
                    "Cannot assign roles — user has no Firebase UID: " + user.getEmail()));
        }

        Set<Roles> roles = user.getRoles();

        if (roles == null || roles.isEmpty()) {
            log.warn("No roles to assign for user {} at {}", user.getEmail(), now);
            return Mono.just(user);
        }

        log.info("Assigning {} role(s) to user {} at {}", roles.size(), user.getEmail(), now);

        return Flux.fromIterable(roles)
                .flatMap(role -> assignSingleRoleWithPermissions(user, role, now))
                .then(resolveAndSetEffectivePermissions(user, now))
                .thenReturn(user);
    }

    /**
     * Assigns a single role with its permissions to a user.
     *
     * Steps:
     *   1. Assign role via PermissionProvider (writes to FirestoreUserPermissions)
     *   2. Add ABAC attributes for the role
     *   3. Set Firebase custom claims for the role
     */
    private Mono<Void> assignSingleRoleWithPermissions(User user, Roles role, Instant now) {
        return permissionProvider.assignRole(user.getId(), role)
                .then(Mono.fromRunnable(() -> addDefaultAttributes(user, role, now))
                        .subscribeOn(Schedulers.boundedElastic()))
                .then(firebaseClaimsService.setClaimsReactive(user.getId(), role))
                .doOnSuccess(v -> {
                    // getPermissionsForRole now returns Set<String> — aligned with v2
                    Set<String> rolePermissions = permissionProvider.getPermissionsForRole(role);
                    log.info("🔐 Role {} assigned with {} permissions to user {} at {}",
                            role, rolePermissions.size(), user.getId(), now);
                    auditLogService.logRoleAssignment(user.getId(), role.name(), "SYSTEM");
                })
                .onErrorResume(e -> {
                    log.error("❌ Error assigning role {} to user {} at {}: {}",
                            role, user.getId(), now, e.getMessage());
                    auditLogService.logRoleAssignmentFailure(
                            user.getId(), role.name(), e.getMessage());
                    return Mono.error(new RuntimeException(
                            "Role assignment failed for " + role + ": " + e.getMessage(), e));
                });
    }

    /**
     * Resolves effective permissions and sets them on the user object.
     *
     * Uses PermissionProvider.resolveEffectivePermissions() which now
     * reads from Firestore via FirestoreRolePermissionsRepository.
     */
    private Mono<User> resolveAndSetEffectivePermissions(User user, Instant now) {
        return Mono.fromCallable(() -> {
                    Set<String> effectivePermissions =
                            permissionProvider.resolveEffectivePermissions(user);
                    user.setAdditionalPermissions(new ArrayList<>(effectivePermissions));

                    log.info("📋 Resolved {} effective permissions for user {} at {}",
                            effectivePermissions.size(), user.getEmail(), now);
                    return user;
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Adds default ABAC attributes for a role to the permission provider.
     * Attributes are ephemeral (in-memory, not persisted to Firestore).
     */
    private void addDefaultAttributes(User user, Roles role, Instant now) {
        String userId = user.getId();

        if (user.getDepartment() != null && !user.getDepartment().isEmpty()) {
            permissionProvider.addUserAttribute(userId, "department", "name",
                    user.getDepartment());
        }

        switch (role) {
            case SUPER_ADMIN -> {
                permissionProvider.addUserAttribute(userId, "access", "level", "super_admin");
                permissionProvider.addUserAttribute(userId, "approval", "can_approve", "all");
            }
            case ADMIN -> {
                permissionProvider.addUserAttribute(userId, "access", "level", "admin");
                permissionProvider.addUserAttribute(userId, "approval", "can_approve",
                        "manager,user");
            }
            case MANAGER -> {
                permissionProvider.addUserAttribute(userId, "access", "level", "manager");
                permissionProvider.addUserAttribute(userId, "approval", "can_approve", "user");
            }
            case USER -> {
                permissionProvider.addUserAttribute(userId, "access", "level", "standard");
            }
            default -> log.debug("No default ABAC attributes defined for role {}", role);
        }

        permissionProvider.addUserAttribute(userId, "registration", "date", now.toString());
        permissionProvider.addUserAttribute(userId, "registration", "requires_approval",
                String.valueOf(user.getStatus() == UserStatus.PENDING_APPROVAL));
    }

    // -------------------------------------------------------------------------
    // Approval notifications
    // -------------------------------------------------------------------------

    /**
     * Sends an approval notification to admins for a pending user.
     * No-op if the user is not in PENDING_APPROVAL status.
     * Non-blocking — notification failure never fails the registration flow.
     *
     * @param user the newly registered user
     * @return Mono completing when the notification attempt finishes
     */
    public Mono<Void> sendApprovalNotification(User user) {
        if (user.getStatus() != UserStatus.PENDING_APPROVAL) {
            return Mono.empty();
        }

        return notificationService.notifyAdminsForApproval(user, user.getApprovalLevel())
                .doOnSuccess(v -> log.info("📧 Approval notification sent for user {} at {}",
                        user.getEmail(), clock.instant()))
                .doOnError(e -> log.warn(
                        "⚠️ Failed to send approval notification for {}: {}",
                        user.getEmail(), e.getMessage()))
                .onErrorResume(e -> Mono.empty()); // non-blocking — notification failure is soft
    }

    // -------------------------------------------------------------------------
    // Validation helpers
    // -------------------------------------------------------------------------

    /**
     * Validates whether self-registration is allowed for all requested roles.
     *
     * Pure CPU logic — returns boolean directly, no Mono needed.
     * The original wrapped this in Mono.fromCallable() unnecessarily.
     *
     * @param user           the user requesting registration
     * @param requestedRoles the roles being requested
     * @return true if all requested roles allow self-registration
     */
    private boolean isSelfRegistrationAllowed(User user, Set<Roles> requestedRoles) {
        if (requestedRoles == null || requestedRoles.isEmpty()) {
            log.warn("⚠️ No roles requested by user {}", user.getEmail());
            return false;
        }

        for (Roles role : requestedRoles) {
            RegistrationRule rule = roleRegistrationRules.get(role);

            if (rule == null) {
                log.error("❌ Unknown role [{}] requested by {} — no registration rule defined",
                        role, user.getEmail());
                return false;
            }

            if (!rule.allowSelfRegistration()) {
                log.warn("🚫 Role [{}] does NOT allow self-registration (requested by {})",
                        role, user.getEmail());
                return false;
            }
        }

        log.info("✅ Self-registration validation passed for {} with roles {}",
                user.getEmail(), requestedRoles);
        return true;
    }

    /**
     * Determines the highest approval level required across all requested roles.
     *
     * Compares approval level order values — highest order wins.
     *
     * @param roles list of roles being assigned
     * @return the highest ApprovalLevel required, defaulting to PENDING_L1
     */
    private ApprovalLevel determineApprovalLevel(List<Roles> roles) {
        ApprovalLevel highest = ApprovalLevel.PENDING_L1;

        for (Roles role : roles) {
            RegistrationRule rule = roleRegistrationRules.get(role);
            if (rule != null) {
                ApprovalLevel ruleLevel = rule.getApprovalLevel();
                if (ruleLevel.getOrder() > highest.getOrder()) {
                    highest = ruleLevel;
                }
            }
        }

        return highest;
    }

    // -------------------------------------------------------------------------
    // Approval validation
    // -------------------------------------------------------------------------

    /**
     * Checks whether the requester in the given SecurityContext can approve
     * the target user based on their role and the target's required approval level.
     *
     * @param securityContext context containing the requester's identity and role
     * @param targetUser      the user awaiting approval
     * @return true if the requester has sufficient privilege to approve
     */
    public boolean canApproveUser(SecurityContext securityContext, User targetUser) {
        ValidationUtils.validateNotNull(securityContext, "Security context cannot be null");
        ValidationUtils.validateNotNull(targetUser, "Target user cannot be null");

        Roles         requesterRole  = securityContext.getRequesterRole();
        ApprovalLevel requiredLevel  = targetUser.getApprovalLevel();
        boolean       canApprove     = canApproveAtLevel(requesterRole, requiredLevel);

        log.debug("🔐 Approval check — requester: {} ({}), target: {}, required: {}, result: {}",
                securityContext.getRequesterEmail(), requesterRole,
                targetUser.getEmail(), requiredLevel != null ? requiredLevel.getDisplayName() : "null",
                canApprove);

        return canApprove;
    }

    /**
     * Determines whether a role has sufficient privilege to approve at a given level.
     *
     * @param requesterRole the approver's role
     * @param requiredLevel the approval level required on the target user
     * @return true if the role can approve at that level
     */
    private boolean canApproveAtLevel(Roles requesterRole, ApprovalLevel requiredLevel) {
        if (requesterRole == null || requiredLevel == null) return false;

        return switch (requiredLevel) {
            case PENDING_L1 ->
                    requesterRole == Roles.MANAGER  ||
                            requesterRole == Roles.ADMIN    ||
                            requesterRole == Roles.SUPER_ADMIN;

            case PENDING_L2 ->
                    requesterRole == Roles.ADMIN    ||
                            requesterRole == Roles.SUPER_ADMIN;

            // Terminal states — no action required or possible
            case NOT_REQUIRED, APPROVED_L1, APPROVED, REJECTED -> false;
        };
    }

    /**
     * Extracts the highest-privilege role from a Spring Security Authentication.
     *
     * @param authentication the authenticated principal
     * @return the highest Roles value found in the authorities
     */
    public Roles extractHighestRole(Authentication authentication) {
        Set<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        if (authorities.contains("ROLE_SUPER_ADMIN")) return Roles.SUPER_ADMIN;
        if (authorities.contains("ROLE_ADMIN"))       return Roles.ADMIN;
        if (authorities.contains("ROLE_MANAGER"))     return Roles.MANAGER;
        return Roles.USER;
    }

    // -------------------------------------------------------------------------
    // Inner class: RegistrationRule
    // -------------------------------------------------------------------------

    /**
     * Configuration for role self-registration behaviour.
     * Immutable — set once in @PostConstruct, never mutated.
     */
    private static class RegistrationRule {

        private final boolean allowSelfRegistration;
        private final boolean requiresApproval;

        @Getter
        private final ApprovalLevel approvalLevel;

        RegistrationRule(
                boolean allowSelfRegistration,
                boolean requiresApproval,
                ApprovalLevel approvalLevel
        ) {
            this.allowSelfRegistration = allowSelfRegistration;
            this.requiresApproval      = requiresApproval;
            this.approvalLevel         = approvalLevel;
        }

        boolean allowSelfRegistration() { return allowSelfRegistration; }
        boolean requiresApproval()      { return requiresApproval;      }
    }
}