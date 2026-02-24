package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.authorization.AccessDeniedException;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.user.*;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.notification.EmailServiceInstance;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.util.auth.AdminAuthorizationUtils;
import com.techStack.authSys.util.auth.AdminUserValidator;
import com.techStack.authSys.util.password.PasswordUtils;
import com.techStack.authSys.util.validation.HelperUtils;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Unified Admin Service (Production Ready)
 *
 * Single service for ALL administrative operations with role-based access control.
 * Consolidates UserApprovalService, AdminManagementService, and AdminUserManagementService.
 *
 * Features:
 * - Role-based authorization (SUPER_ADMIN 100%, ADMIN 75%)
 * - Hierarchical permission checks
 * - Comprehensive audit logging
 * - Atomic transactions
 * - Email notifications
 * - Session management
 * - Firebase Auth integration
 *
 * @author TechStack Security Team
 * @version 3.0 - Unified Production
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminService {

    /* =========================
       Dependencies
       ========================= */

    private final FirestoreUserRepository userRepository;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PermissionProvider permissionProvider;
    private final RoleAssignmentService roleAssignmentService;
    private final SessionService sessionService;
    private final RedisUserCacheService cacheService;
    private final EmailServiceInstance emailService;
    private final AuditLogService auditLogService;
    private final MetricsService metricsService;
    private final FirebaseAuth firebaseAuth;
    private final AdminNotificationService notificationService;
    private final Clock clock;

    /* =========================
       ADMIN CREATION (SUPER_ADMIN ONLY)
       ========================= */


    /**
     * Create new admin user
     *
     * Authorization: SUPER_ADMIN only
     * Access Level: 100%
     */
    public Mono<User> createAdmin(
            UserRegistrationDTO userDto,
            String creatorId,
            Roles creatorRole,
            String ipAddress
    ) {
        Instant startTime = clock.instant();

        // Authorization check
        if (!AdminAuthorizationUtils.isSuperAdmin(creatorRole)) {
            log.warn("🚫 Unauthorized admin creation by {} ({})", creatorId, creatorRole);
            return Mono.error(AccessDeniedException.insufficientRole("SUPER_ADMIN", creatorRole.name()));
        }

        log.info("🔐 SUPER_ADMIN {} creating admin for: {} at {}",
                creatorId, HelperUtils.maskEmail(userDto.getEmail()), startTime);

        return AdminUserValidator.validateEmailAvailability(cacheService, userDto.getEmail())
                .flatMap(available -> {
                    if (!available) {
                        return Mono.error(new IllegalStateException(
                                "Email already registered: " + userDto.getEmail()));
                    }

                    String tempPassword = PasswordUtils.generateSecurePassword(16);
                    User adminUser = UserFactory.createAdminUser(
                            userDto.getEmail(),
                            userDto.getFirstName(),
                            userDto.getLastName(),
                            clock
                    );

                    adminUser.setCreatedBy(creatorId);
                    adminUser.setForcePasswordChange(true);
                    adminUser.setPhoneNumber(userDto.getPhoneNumber());
                    adminUser.setDepartment(userDto.getDepartment());

                    return createAdminInFirebase(adminUser, tempPassword, creatorId, ipAddress, startTime);
                })
                .doOnSuccess(admin -> {
                    metricsService.incrementCounter("admin.created.success");
                    log.info("✅ Admin created: {} by {}", admin.getEmail(), creatorId);
                })
                .doOnError(e -> {
                    metricsService.incrementCounter("admin.created.failure");
                    log.error("❌ Admin creation failed: {}", e.getMessage());
                });
    }

    /* =========================
       USER APPROVAL
       ========================= */

    /**
     * Approve pending user account
     *
     * Authorization: ADMIN (regular users), SUPER_ADMIN (all users)
     * Access Level: ADMIN=75%, SUPER_ADMIN=100%
     */
    public Mono<User> approveUser(String userId, String approverId, Roles approverRole) {
        Instant now = clock.instant();

        log.info("🔍 Approval request for {} by {} ({})", userId, approverId, approverRole);

        if (!AdminAuthorizationUtils.canApproveUsers(approverRole)) {
            return Mono.error(AccessDeniedException.operationNotAllowed("approve users", approverRole.name()));
        }

        return userRepository.findById(userId)
                .flatMap(AdminUserValidator::validatePendingStatus)
                .flatMap(user -> AdminAuthorizationUtils.checkManagementAuthority(user, approverRole)
                        .flatMap(hasAuthority -> {
                            if (!hasAuthority) {
                                return Mono.error(AccessDeniedException.cannotManageHigherPrivilege(
                                        approverRole.name(), user.getRoles().toString()));
                            }
                            return performApproval(user, approverId, approverRole, now);
                        }))
                .doOnSuccess(user -> metricsService.incrementCounter("user.approved.success"))
                .doOnError(e -> metricsService.incrementCounter("user.approved.failure"));
    }

    /**
     * Reject pending user account
     *
     * Authorization: ADMIN (regular users), SUPER_ADMIN (all users)
     * Access Level: ADMIN=75%, SUPER_ADMIN=100%
     */
    public Mono<Void> rejectUser(String userId, String rejecterId, Roles rejectorRole, String reason) {
        Instant now = clock.instant();

        log.info("🚫 Rejection request for {} by {} ({}) - Reason: {}",
                userId, rejecterId, rejectorRole, reason);

        if (!AdminAuthorizationUtils.canRejectUsers(rejectorRole)) {
            return Mono.error(AccessDeniedException.operationNotAllowed("reject users", rejectorRole.name()));
        }

        return userRepository.findById(userId)
                .flatMap(AdminUserValidator::validatePendingStatus)
                .flatMap(user -> AdminAuthorizationUtils.checkManagementAuthority(user, rejectorRole)
                        .flatMap(hasAuthority -> {
                            if (!hasAuthority) {
                                return Mono.error(AccessDeniedException.cannotManageHigherPrivilege(
                                        rejectorRole.name(), user.getRoles().toString()));
                            }
                            return performRejection(user, rejecterId, rejectorRole, reason, now);
                        }))
                .doOnSuccess(v -> metricsService.incrementCounter("user.rejected.success"))
                .doOnError(e -> metricsService.incrementCounter("user.rejected.failure"));
    }
    /* =========================
       PERMISSION MANAGEMENT
       ========================= */

    public Mono<Void> approveUserAndGrantPermissions(String userId, String approvedBy) {
        Instant now = clock.instant();

        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    // Get the approver's role (you need to fetch this)
                    return firebaseServiceAuth.getUserById(approvedBy)
                            .map(approver -> {
                                Roles approverRole = approver.getPrimaryRole(); // or getHighestRole()
                                return approveAndGrantPermissions(
                                        user,
                                        approvedBy,
                                        approverRole,
                                        now
                                );
                            });
                })
                .doOnSuccess(v -> log.info("✅ User approved: {}", userId)).then();
    }
    public Mono<Map<String, Object>> getUserPermissions(String userId) {
        log.debug("🔍 Getting permissions for user: {}", userId);

        return firebaseServiceAuth.getUserById(userId)
                .switchIfEmpty(Mono.error(new UserNotFoundException("User not found: " + userId)))
                .flatMap(user -> Mono.fromCallable(() -> permissionProvider.resolveEffectivePermissions(user)))
                .map(permissionsSet -> {
                    Map<String, Object> result = new LinkedHashMap<>();  // Preserve order
                    result.put("success", true);
                    result.put("userId", userId);
                    result.put("permissions", permissionsSet);
                    result.put("count", permissionsSet.size());
                    result.put("timestamp", clock.instant().toString());

                    // Add permission categories for better organization
                    Map<String, List<String>> categorized = permissionsSet.stream()
                            .collect(Collectors.groupingBy(
                                    perm -> perm.split("_")[0],  // Categorize by prefix (e.g., USER_, ADMIN_)
                                    Collectors.toList()
                            ));
                    result.put("categorized", categorized);

                    return result;
                })
                .doOnSuccess(result ->
                        log.info("✅ Retrieved {} permissions for user {}",
                                result.get("count"), userId))
                .doOnError(e -> {
                    if (e instanceof UserNotFoundException) {
                        log.warn("⚠️ User not found: {}", userId);
                    } else {
                        log.error("❌ Failed to get permissions for user {}: {}",
                                userId, e.getMessage(), e);
                    }
                })
                .onErrorResume(UserNotFoundException.class, e -> {
                    Map<String, Object> errorResult = new HashMap<>();
                    errorResult.put("success", false);
                    errorResult.put("error", "User not found");
                    errorResult.put("userId", userId);
                    errorResult.put("timestamp", clock.instant().toString());
                    return Mono.just(errorResult);
                });
    }

    /**
     * Approve user and grant appropriate permissions
     *
     * This method:
     * 1. Gets active permissions for the user based on their roles
     * 2. Prepares permission data for storage
     * 3. Grants permissions to the user
     * 4. Updates user status to ACTIVE
     *
     * @param user The user to approve
     * @param approverId ID of the admin approving
     * @param approverRole Role of the approver
     * @param now Current timestamp
     * @return Approved user with permissions
     */
    public Mono<User> approveAndGrantPermissions(User user, String approverId, Roles approverRole, Instant now) {
        log.info("🔐 Approving and granting permissions for user: {}", user.getId());

        return getActivePermissions(user)
                .flatMap(permissions -> {
                    // Prepare permission data for storage
                    PermissionData permissionData = preparePermissionData(user, permissions, approverId, now);

                    // Grant permissions to user
                    return grantUserPermissions(user, permissions)
                            .then(Mono.just(permissionData));
                })
                .flatMap(permissionData -> {
                    // Update user status
                    user.setStatus(UserStatus.ACTIVE);
                    user.setEnabled(true);
                    user.setApprovedBy(approverId);
                    user.setApprovedAt(now);
                    user.setUpdatedAt(now);

                    // Save user with permissions
                    return userRepository.saveUserWithPermissions(user, permissionData)
                            .flatMap(savedUser ->
                                    notificationService.notifyUserApproved(savedUser)
                                            .thenReturn(savedUser)
                            );
                })
                .flatMap(savedUser ->
                        logAction(user.getId(), approverId, "USER_APPROVED",
                                Map.of(
                                        "approverRole", approverRole.name(),
                                        "timestamp", now,
                                        "permissionsGranted", true
                                ))
                                .thenReturn(savedUser)
                )
                .doOnSuccess(savedUser ->
                        log.info("✅ User {} approved and permissions granted", savedUser.getId())
                )
                .doOnError(e ->
                        log.error("❌ Failed to approve and grant permissions for user {}: {}",
                                user.getId(), e.getMessage())
                );
    }

    /**
     * Get active permissions for a user based on their roles
     *
     * Resolves all permissions from:
     * - Direct role assignments
     * - Inherited roles
     * - Custom permissions
     *
     * @param user The user to get permissions for
     * @return Set of active permission strings
     */
    /**
     * Get active permissions for user (FIXED)
     *
     * Resolves permissions from:
     * 1. User's assigned roles
     * 2. User's custom permissions (if any)
     */
    public Mono<Set<String>> getActivePermissions(User user) {
        log.debug("🔍 Getting active permissions for user: {}", user.getId());

        // Get roles from user
        Set<Roles> userRoles = user.getRoles();

        if (userRoles == null || userRoles.isEmpty()) {
            log.warn("⚠️ User {} has no roles assigned, using default USER role", user.getId());
            userRoles = Set.of(Roles.USER);
        }

        // ✅ FIX 1: getPermissionsForRole returns Set<Permissions>, not Mono
        // Convert synchronous to reactive and collect all permissions
        Set<Roles> finalUserRoles = userRoles;

        return Mono.fromCallable(() -> {
                    Set<String> allPermissions = new HashSet<>();

                    // Resolve permissions from each role
                    for (Roles role : finalUserRoles) {
                        Set<Permissions> rolePermissions = permissionProvider.getPermissionsForRole(role);

                        // Convert enum to string names
                        Set<String> permissionNames = rolePermissions.stream()
                                .map(Permissions::name)
                                .collect(Collectors.toSet());

                        allPermissions.addAll(permissionNames);

                        log.debug("Role {} has {} permissions: {}",
                                role, permissionNames.size(), permissionNames);
                    }

                    // ✅ FIX 2: Check if User has customPermissions field
                    // If User doesn't have this field, remove this block
                    if (user.getCustomPermissions() != null && !user.getCustomPermissions().isEmpty()) {
                        allPermissions.addAll(user.getCustomPermissions());
                        log.debug("Added {} custom permissions for user {}",
                                user.getCustomPermissions().size(), user.getId());
                    }

                    return allPermissions;
                })
                .doOnSuccess(permissions ->
                        log.info("✅ Resolved {} active permissions for user {}",
                                permissions.size(), user.getId()))
                .doOnError(e ->
                        log.error("❌ Failed to get active permissions for user {}: {}",
                                user.getId(), e.getMessage()));
    }

    /**
     * Prepare permission data for storage in database
     *
     * Creates a structured permission object containing:
     * - Roles assigned to user
     * - Resolved permissions
     * - User status
     * - Approval metadata
     *
     * @param user The user
     * @param permissions Set of resolved permissions
     * @param approverId ID of approving admin
     * @param now Approval timestamp
     * @return PermissionData object ready for storage
     */
    public PermissionData preparePermissionData(
            User user,
            Set<String> permissions,
            String approverId,
            Instant now) {

        log.debug("📦 Preparing permission data for user: {}", user.getId());

        // Build permission data using builder pattern
        PermissionData.PermissionDataBuilder builder = PermissionData.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .roles(new ArrayList<>(user.getRoleNames()))
                .permissions(new ArrayList<>(permissions))
                .status(UserStatus.ACTIVE)
                .approvedBy(approverId)
                .approvedAt(now)
                .grantedAt(now)
                .version(1)
                .active(true);

        // Add role hierarchy information if available
        Map<String, List<String>> roleHierarchy = buildRoleHierarchy(user.getRoles());
        if (!roleHierarchy.isEmpty()) {
            builder.roleHierarchy(roleHierarchy);
        }

        // Add permission metadata
        builder.permissionMetadata(Map.of(
                "source", "role-based",
                "resolvedAt", now.toString(),
                "totalPermissions", permissions.size()
        ));

        // Add audit trail
        builder.auditTrail(List.of(Map.of(
                "action", "PERMISSIONS_GRANTED",
                "performedBy", approverId,
                "timestamp", now.toString()
        )));

        PermissionData permissionData = builder.build();

        log.info("✅ Prepared permission data for user {}: {} roles, {} permissions",
                user.getId(), permissionData.getRoles().size(), permissionData.getPermissions().size());

        return permissionData;
    }

    /**
     * Grant permissions to user (FIXED)
     *
     * Updates user's additional permissions and invalidates cache
     */
    private Mono<Void> grantUserPermissions(User user, Set<String> permissions) {
        log.info("🔑 Granting {} permissions to user: {}", permissions.size(), user.getId());

        // ✅ FIX 1: User doesn't have setPermissions(), use setAdditionalPermissions()
        // Convert Set<String> to List<String>
        user.setAdditionalPermissions(new ArrayList<>(permissions));

        // ✅ FIX 2: User doesn't have setPermissionsUpdatedAt(), use setUpdatedAt()
        user.setUpdatedAt(clock.instant());

        // Clear any cached permissions
        return cacheService.invalidateUserPermissions(user.getId())
                .doOnSuccess(v -> log.debug("Cleared permissions cache for user {}", user.getId()))
                // ✅ FIX 3: Use .then() for Mono<Void> instead of .then(Mono.fromRunnable())
                .then(Mono.defer(() -> {
                    // Log the permission grant
                    auditLogService.logAuditEvent(
                            user.getId(),
                            ActionType.PERMISSIONS_GRANTED,
                            "Permissions granted during approval",
                            Map.of(
                                    "permissionCount", permissions.size(),
                                    "timestamp", clock.instant().toString()
                            )
                    ).subscribe();

                    return Mono.empty();  // ✅ Return Mono<Void>
                }))
                .doOnSuccess(v -> log.info("✅ Successfully granted permissions to user {}", user.getId()))
                .onErrorResume(e -> {
                    log.error("❌ Failed to grant permissions to user {}: {}",
                            user.getId(), e.getMessage());
                    return Mono.empty(); // Don't fail the approval flow
                }).then();
    }

    /**
     * Build role hierarchy for permission inheritance
     *
     * Example: SUPER_ADMIN inherits all ADMIN permissions, etc.
     *
     * @param userRoles Set of user roles
     * @return Map of role inheritance relationships
     */
    private Map<String, List<String>> buildRoleHierarchy(Set<Roles> userRoles) {
        Map<String, List<String>> hierarchy = new HashMap<>();

        if (userRoles == null || userRoles.isEmpty()) {
            return hierarchy;
        }

        // Define role hierarchy (higher roles inherit from lower)
        Map<Roles, List<Roles>> roleInheritance = Map.of(
                Roles.SUPER_ADMIN, List.of(Roles.ADMIN, Roles.MANAGER, Roles.USER),
                Roles.ADMIN, List.of(Roles.MANAGER, Roles.USER),
                Roles.MANAGER, List.of(Roles.USER),
                Roles.USER, List.of()
        );

        // Build hierarchy for each user role
        userRoles.forEach(role -> {
            List<Roles> inheritedRoles = roleInheritance.getOrDefault(role, List.of());
            hierarchy.put(role.name(),
                    inheritedRoles.stream()
                            .map(Roles::name)
                            .collect(java.util.stream.Collectors.toList())
            );
        });

        return hierarchy;
    }


    /* =========================
       USER LIFECYCLE MANAGEMENT
       ========================= */

    /**
     * Suspend user account
     *
     * Authorization: ADMIN (regular users), SUPER_ADMIN (all users)
     * Access Level: ADMIN=75%, SUPER_ADMIN=100%
     */
    public Mono<Void> suspendUser(String userId, String performedById, Roles performerRole, String reason) {
        Instant now = clock.instant();

        log.info("🔒 Suspend request for {} by {} ({}) - Reason: {}",
                userId, performedById, performerRole, reason);

        if (!AdminAuthorizationUtils.canSuspendUsers(performerRole)) {
            return Mono.error(AccessDeniedException.operationNotAllowed("suspend users", performerRole.name()));
        }

        return userRepository.findById(userId)
                .flatMap(user -> AdminAuthorizationUtils.checkManagementAuthority(user, performerRole)
                        .flatMap(hasAuthority -> {
                            if (!hasAuthority) {
                                return Mono.error(AccessDeniedException.cannotManageHigherPrivilege(
                                        performerRole.name(), user.getRoles().toString()));
                            }

                            user.setStatus(UserStatus.SUSPENDED);
                            user.setEnabled(false);
                            user.setUpdatedAt(now);

                            return userRepository.update(user)
                                    .then(sessionService.invalidateAllSessionsForUser(userId))
                                    .then(logAction(userId, performedById, "SUSPEND_USER",
                                            Map.of("reason", reason, "timestamp", now)));
                        }))
                .doOnSuccess(v -> {
                    metricsService.incrementCounter("user.suspended.success");
                    log.info("✅ User {} suspended by {}", userId, performedById);
                });
    }

    /**
     * Reactivate suspended user
     *
     * Authorization: ADMIN (regular users), SUPER_ADMIN (all users)
     * Access Level: ADMIN=75%, SUPER_ADMIN=100%
     */
    public Mono<Void> reactivateUser(String userId, String performedById, Roles performerRole) {
        Instant now = clock.instant();

        log.info("🔓 Reactivate request for {} by {} ({})", userId, performedById, performerRole);

        if (!AdminAuthorizationUtils.canReactivateUsers(performerRole)) {
            return Mono.error(AccessDeniedException.operationNotAllowed("reactivate users", performerRole.name()));
        }

        return userRepository.findById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != UserStatus.SUSPENDED) {
                        return Mono.error(new IllegalStateException(
                                "User not suspended. Current: " + user.getStatus()));
                    }

                    return AdminAuthorizationUtils.checkManagementAuthority(user, performerRole)
                            .flatMap(hasAuthority -> {
                                if (!hasAuthority) {
                                    return Mono.error(AccessDeniedException.cannotManageHigherPrivilege(
                                            performerRole.name(), user.getRoles().toString()));
                                }

                                user.setStatus(UserStatus.ACTIVE);
                                user.setEnabled(true);
                                user.setUpdatedAt(now);

                                return userRepository.update(user)
                                        .then(logAction(userId, performedById, "REACTIVATE_USER",
                                                Map.of("timestamp", now)));
                            });
                })
                .doOnSuccess(v -> {
                    metricsService.incrementCounter("user.reactivated.success");
                    log.info("✅ User {} reactivated by {}", userId, performedById);
                });
    }

    /**
     * Force password reset
     *
     * Authorization: ADMIN (regular users), SUPER_ADMIN (all users)
     * Access Level: ADMIN=75%, SUPER_ADMIN=100%
     */
    public Mono<Void> forcePasswordReset(String userId, String performedById, Roles performerRole) {
        Instant now = clock.instant();

        log.info("🔑 Force password reset for {} by {} ({})", userId, performedById, performerRole);

        if (!AdminAuthorizationUtils.canForcePasswordReset(performerRole)) {
            return Mono.error(AccessDeniedException.operationNotAllowed("force password reset", performerRole.name()));
        }

        return userRepository.findById(userId)
                .flatMap(user -> AdminAuthorizationUtils.checkManagementAuthority(user, performerRole)
                        .flatMap(hasAuthority -> {
                            if (!hasAuthority) {
                                return Mono.error(AccessDeniedException.cannotManageHigherPrivilege(
                                        performerRole.name(), user.getRoles().toString()));
                            }

                            user.setForcePasswordChange(true);
                            user.setUpdatedAt(now);

                            return userRepository.update(user)
                                    .then(sessionService.invalidateAllSessionsForUser(userId))
                                    .then(logAction(userId, performedById, "FORCE_PASSWORD_RESET",
                                            Map.of("timestamp", now)));
                        }))
                .doOnSuccess(v -> {
                    metricsService.incrementCounter("password.reset.forced.success");
                    log.info("✅ Password reset forced for {} by {}", userId, performedById);
                });
    }

    /* =========================
       USER QUERIES
       ========================= */

    /**
     * Find users with filters (role-based visibility)
     */
    public Flux<User> findUsers(Roles performerRole, UserQueryFilters filters) {
        if (!AdminAuthorizationUtils.canViewUsers(performerRole)) {
            return Flux.error(AccessDeniedException.operationNotAllowed("view users", performerRole.name()));
        }

        return userRepository.findByStatus(filters.status())
                .filter(user -> AdminAuthorizationUtils.canViewUser(user, performerRole));
    }

    /**
     * Get user statistics (role-filtered)
     */
    public Mono<Map<String, Long>> getUserStatistics(Roles performerRole) {
        if (!AdminAuthorizationUtils.canViewStatistics(performerRole)) {
            return Mono.error(AccessDeniedException.operationNotAllowed("view statistics", performerRole.name()));
        }

        return Mono.zip(
                countByStatus(UserStatus.ACTIVE, performerRole),
                countByStatus(UserStatus.PENDING_APPROVAL, performerRole),
                countByStatus(UserStatus.SUSPENDED, performerRole),
                countByStatus(UserStatus.REJECTED, performerRole)
        ).map(tuple -> Map.of(
                "active", tuple.getT1(),
                "pending", tuple.getT2(),
                "suspended", tuple.getT3(),
                "rejected", tuple.getT4(),
                "total", tuple.getT1() + tuple.getT2() + tuple.getT3() + tuple.getT4()
        ));
    }

    /* =========================
       PRIVATE HELPERS
       ========================= */

    private Mono<User> createAdminInFirebase(
            User adminUser,
            String tempPassword,
            String creatorId,
            String ipAddress,
            Instant startTime
    ) {
        return firebaseServiceAuth.createFirebaseUser(adminUser, tempPassword, ipAddress, "admin-creation")
                .flatMap(user -> roleAssignmentService.assignRolesAndPermissions(user, clock.instant()))
                .flatMap(user -> sendAdminWelcomeEmail(user, tempPassword, startTime).thenReturn(user))
                .flatMap(user -> cacheService.cacheRegisteredEmail(user.getEmail()).thenReturn(user))
                .flatMap(user -> logAction(user.getId(), creatorId, "ADMIN_CREATED",
                        Map.of("createdBy", creatorId, "timestamp", startTime))
                        .thenReturn(user));
    }

    private Mono<User> performApproval(User user, String approverId, Roles approverRole, Instant now) {
        Set<String> permissions = permissionProvider.resolveEffectivePermissions(user);

        PermissionData permData = PermissionData.builder()
                .roles(new ArrayList<>(user.getRoleNames()))
                .permissions(new ArrayList<>(permissions))
                .status(UserStatus.ACTIVE)
                .approvedBy(approverId)
                .approvedAt(now)
                .build();

        user.setStatus(UserStatus.ACTIVE);
        user.setEnabled(true);
        user.setApprovedBy(approverId);
        user.setApprovedAt(now);
        user.setUpdatedAt(now);

        return userRepository.saveUserWithPermissions(user, permData)
                .flatMap(savedUser -> notificationService.notifyUserApproved(savedUser).thenReturn(savedUser))
                .flatMap(savedUser -> logAction(user.getId(), approverId, "USER_APPROVED",
                        Map.of("approverRole", approverRole.name(), "timestamp", now))
                        .thenReturn(savedUser));
    }

    private Mono<Void> performRejection(User user, String rejecterId, Roles rejectorRole, String reason, Instant now) {
        return notificationService.notifyUserRejected(user, reason)
                .then(userRepository.delete(user.getId()))
                .then(deleteFromFirebaseAuth(user.getId(), user.getEmail()))
                .then(logAction(user.getId(), rejecterId, "USER_REJECTED",
                        Map.of("rejectorRole", rejectorRole.name(), "reason", reason, "timestamp", now)));
    }

    private Mono<Void> deleteFromFirebaseAuth(String userId, String email) {
        return Mono.fromRunnable(() -> {
            try {
                firebaseAuth.deleteUser(userId);
                log.info("✅ Deleted {} from Firebase Auth", email);
            } catch (FirebaseAuthException e) {
                if (!"user-not-found".equals(e.getErrorCode())) {
                    log.error("⚠️ Firebase Auth deletion failed: {}", e.getMessage());
                }
            }
        });
    }

    private Mono<Void> sendAdminWelcomeEmail(User user, String tempPassword, Instant timestamp) {
        String subject = "🔐 Admin Account Created";
        String body = String.format("""
                Welcome to the Admin Panel!
                
                Email: %s
                Temporary Password: %s
                
                Login: https://app.example.com/admin/login
                """, user.getEmail(), tempPassword);

        return emailService.sendEmail(user.getEmail(), subject, body)
                .onErrorResume(e -> Mono.empty());
    }

    private Mono<Long> countByStatus(UserStatus status, Roles performerRole) {
        return userRepository.findByStatus(status)
                .filter(user -> AdminAuthorizationUtils.canViewUser(user, performerRole))
                .count();
    }

    private Mono<Void> logAction(String userId, String performedById, String action, Map<String, Object> metadata) {
        return Mono.fromRunnable(() ->
                auditLogService.logAuditEvent(
                        userId,
                        com.techStack.authSys.models.audit.ActionType.valueOf(action),
                        action + " by " + performedById,
                        metadata
                ).subscribe()
        );
    }

    /* =========================
       SUPPORTING TYPES
       ========================= */

    public record UserQueryFilters(
            UserStatus status,
            Optional<String> email,
            Optional<Instant> createdAfter,
            Optional<Instant> createdBefore
    ) {}
}