package com.techStack.authSys.service.user;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.user.*;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.authorization.PermissionService;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.observability.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.*;

import static com.techStack.authSys.models.audit.ActionType.RESTORED;

/**
 * User Approval Service
 *
 * Single Responsibility: Handle user approval/rejection workflow
 *
 * Responsibilities:
 * - Approve pending users
 * - Reject pending users
 * - Restore rejected users
 * - Validate approver authority
 * - Grant permissions upon approval
 *
 * Does NOT:
 * - Suspend/reactivate users (that's AdminManagementService)
 * - Query users (that's AdminManagementService)
 * - Manage passwords (that's UserService)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserApprovalService {

    /* =========================
       Dependencies
       ========================= */

    private final FirestoreUserRepository userRepository;
    private final PermissionService permissionService;
    private final RoleAssignmentService roleAssignmentService;
    private final AdminNotificationService notificationService;
    private final AuditLogService auditLogService;
    private final FirebaseAuth firebaseAuth;
    private final Clock clock;

    /* =========================
       Permission Preparation
       ========================= */

    /**
     * Prepare permission data for a user based on their status
     */
    public Mono<PermissionData> preparePermissionData(User user) {
        return Mono.fromCallable(() -> {
            Instant now = clock.instant();

            // Pending users get empty permissions
            if (user.getStatus() == UserStatus.PENDING_APPROVAL) {
                log.debug("Preparing empty permissions for pending user: {}", user.getEmail());

                return PermissionData.builder()
                        .roles(new ArrayList<>(user.getRoleNames()))
                        .permissions(Collections.emptyList())
                        .status(UserStatus.PENDING_APPROVAL)
                        .approvedBy(null)
                        .approvedAt(null)
                        .build();
            }

            // Active/Approved users get full permissions
            Set<String> permissions = permissionService.resolveEffectivePermissions(user);

            log.debug("Preparing {} permissions for active user: {}",
                    permissions.size(), user.getEmail());

            return PermissionData.builder()
                    .roles(new ArrayList<>(user.getRoleNames()))
                    .permissions(new ArrayList<>(permissions))
                    .status(UserStatus.ACTIVE)
                    .approvedBy(user.getCreatedBy() != null ? user.getCreatedBy() : "SYSTEM")
                    .approvedAt(now)
                    .build();
        });
    }

    /* =========================
       User Approval
       ========================= */

    /**
     * Approve user account with full role validation
     *
     * @param userId User to approve
     * @param approvedBy ID of approver
     * @param approverRole Role of approver
     * @return Approved user
     */
    public Mono<User> approveUserAccount(
            String userId,
            String approvedBy,
            Roles approverRole
    ) {
        Instant now = clock.instant();

        log.info("🔍 Approval request for user {} by {} ({})", userId, approvedBy, approverRole);

        return userRepository.findById(userId)
                .flatMap(user -> validatePendingStatus(user))
                .flatMap(user -> validateApproverAuthority(user, approverRole)
                        .flatMap(hasAuthority -> {
                            if (!hasAuthority) {
                                log.warn("🚫 Unauthorized approval attempt by {} ({}) for user {}",
                                        approvedBy, approverRole, user.getEmail());

                                auditLogService.logUnauthorizedApproval(
                                        userId, approvedBy, approverRole.name());

                                return Mono.error(new SecurityException(
                                        "Approver role " + approverRole +
                                                " insufficient to approve user with roles " + user.getRoles()));
                            }

                            return performApproval(user, approvedBy, approverRole, now);
                        }))
                .doOnError(e -> log.error("❌ Failed to approve user {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /**
     * Approve pending user (simplified version without role validation)
     *
     * @param userId User to approve
     * @param performedById ID of approver
     * @return Void
     */
    public Mono<Void> approvePendingUser(String userId, String performedById) {
        log.info("📋 Simple approval for user {} by {}", userId, performedById);

        return userRepository.findById(userId)
                .flatMap(this::validatePendingStatus)
                .flatMap(user -> performSimpleApproval(user, performedById))
                .onErrorResume(e -> {
                    log.error("❌ Failed to approve user {}: {}", userId, e.getMessage());
                    auditLogService.logApprovalAction(userId, performedById, "APPROVAL_FAILED", "");
                    return Mono.error(e);
                });
    }

    /**
     * Approve and assign role (legacy compatibility method)
     */
    public Mono<Void> approveAndAssignRole(User user, String performedById) {
        return Mono.just(user)
                .flatMap(u -> {
                    // Validate not already approved
                    if (u.getStatus() == UserStatus.ACTIVE && u.getRoleNames() != null) {
                        return Mono.error(new IllegalStateException(
                                "User already has active status and roles assigned"));
                    }

                    return performSimpleApproval(u, performedById);
                });
    }

    /**
     * Grant permissions to approved user
     */
    public Mono<Void> approveAndGrantPermissions(User user, String approvedBy) {
        return Mono.fromCallable(() -> {
                    Instant now = clock.instant();

                    // Resolve effective permissions
                    Set<String> permissions = permissionService.resolveEffectivePermissions(user);

                    if (permissions.isEmpty()) {
                        log.error("❌ Resolved permissions are empty for user {}", user.getEmail());
                        throw new IllegalStateException(
                                "Resolved permissions are empty for user " + user.getEmail());
                    }

                    log.info("✅ Granting {} permissions to user {}", permissions.size(), user.getEmail());

                    // Build permission data
                    PermissionData permData = PermissionData.builder()
                            .roles(new ArrayList<>(user.getRoleNames()))
                            .permissions(new ArrayList<>(permissions))
                            .status(UserStatus.ACTIVE)
                            .approvedBy(approvedBy)
                            .approvedAt(now)
                            .build();

                    return permData;
                })
                .flatMap(permData -> {
                    // Update user status
                    user.setStatus(UserStatus.ACTIVE);
                    user.setEnabled(true);
                    user.setApprovedBy(approvedBy);
                    user.setApprovedAt(clock.instant());

                    // Save user with permissions atomically
                    return userRepository.saveUserWithPermissions(user, permData);
                })
                .doOnSuccess(v -> log.info("✅ User {} approved with permissions", user.getEmail()))
                .then();
    }

    /* =========================
       User Rejection
       ========================= */

    /**
     * Reject user account with validation
     *
     * @param userId User to reject
     * @param rejectedBy ID of rejector
     * @param rejectorRole Role of rejector
     * @param reason Rejection reason
     */
    public Mono<Void> rejectUserAccount(
            String userId,
            String rejectedBy,
            Roles rejectorRole,
            String reason
    ) {
        Instant now = clock.instant();

        log.info("🚫 Rejection request for user {} by {} ({}) - Reason: {}",
                userId, rejectedBy, rejectorRole, reason);

        return userRepository.findById(userId)
                .flatMap(user -> validatePendingStatus(user))
                .flatMap(user -> validateApproverAuthority(user, rejectorRole)
                        .flatMap(hasAuthority -> {
                            if (!hasAuthority) {
                                log.warn("🚫 Unauthorized rejection attempt by {} ({}) for user {}",
                                        rejectedBy, rejectorRole, user.getEmail());

                                return Mono.error(new SecurityException(
                                        "Rejector role " + rejectorRole +
                                                " insufficient to reject user"));
                            }

                            return performRejection(user, rejectedBy, rejectorRole, reason, now);
                        }))
                .doOnError(e -> log.error("❌ Failed to reject user {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /**
     * Reject user account (simplified version)
     *
     * @param userId User to reject
     * @param rejectedBy ID of rejector
     * @param reason Rejection reason
     */
    public Mono<Void> rejectUserAccount(
            String userId,
            String rejectedBy,
            String reason
    ) {
        Instant now = clock.instant();

        log.info("🗑️ Simple rejection for user {} by {} - Reason: {}",
                userId, rejectedBy, reason);

        return userRepository.findById(userId)
                .flatMap(user -> validatePendingStatus(user))
                .flatMap(user -> performSimpleRejection(user, rejectedBy, reason, now))
                .doOnError(e -> log.error("❌ Failed to reject user {}: {}", userId, e.getMessage()));
    }

    /**
     * Reject pending user and set status to REJECTED
     */
    public Mono<Void> rejectPendingUser(String userId, String performedById) {
        Instant now = clock.instant();

        log.info("📝 Setting user {} to REJECTED status by {}", userId, performedById);

        return userRepository.findById(userId)
                .flatMap(user -> {
                    user.setStatus(UserStatus.REJECTED);
                    user.setUpdatedAt(now);

                    return userRepository.update(user);
                })
                .doOnSuccess(v -> {
                    auditLogService.logApprovalAction(
                            userId, performedById, "REJECTED", "", "Set to REJECTED status");
                    log.info("✅ User {} set to REJECTED status", userId);
                })
                .then();
    }

    /* =========================
       User Restoration
       ========================= */

    /**
     * Restore rejected user back to pending approval
     *
     * @param userId User to restore
     * @param restoredBy ID of restorer
     * @param restorerRole Role of restorer
     */
    public Mono<Void> restoreRejectedUser(
            String userId,
            String restoredBy,
            Roles restorerRole
    ) {
        Instant now = clock.instant();

        log.info("♻️ Restoration request for user {} by {} ({})",
                userId, restoredBy, restorerRole);

        return userRepository.findById(userId)
                .flatMap(user -> {
                    // Validate user is rejected
                    if (user.getStatus() != UserStatus.REJECTED) {
                        return Mono.error(new IllegalStateException(
                                "User is not in REJECTED status. Current: " + user.getStatus()));
                    }

                    return validateApproverAuthority(user, restorerRole)
                            .flatMap(hasAuthority -> {
                                if (!hasAuthority) {
                                    log.warn("🚫 Unauthorized restoration attempt by {} ({}) for user {}",
                                            restoredBy, restorerRole, user.getEmail());

                                    return Mono.error(new SecurityException(
                                            "Role " + restorerRole +
                                                    " insufficient to restore user account"));
                                }

                                return performRestoration(user, restoredBy, now);
                            });
                })
                .doOnError(e -> log.error("❌ Failed to restore user {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /* =========================
       Read Operations
       ========================= */

    /**
     * Get active permissions for a user
     */
    public Mono<Map<String, Object>> getActivePermissions(String userId) {
        log.debug("📋 Fetching active permissions for user {}", userId);

        return userRepository.getUserPermissions(userId)
                .doOnSuccess(perms -> log.debug("✅ Retrieved permissions for user {}", userId))
                .doOnError(e -> log.error("❌ Failed to get permissions for {}: {}",
                        userId, e.getMessage()));
    }

    /* =========================
       Private Helper Methods
       ========================= */

    /**
     * Validate user is in pending approval status
     */
    private Mono<User> validatePendingStatus(User user) {
        if (user.getStatus() != UserStatus.PENDING_APPROVAL) {
            log.warn("⚠️ User {} is not pending approval. Current status: {}",
                    user.getEmail(), user.getStatus());

            return Mono.error(new IllegalStateException(
                    "User " + user.getEmail() + " is not pending approval. Current status: " +
                            user.getStatus()));
        }
        return Mono.just(user);
    }

    /**
     * Validate approver has sufficient authority based on ApprovalLevel workflow.
     */
    private Mono<Boolean> validateApproverAuthority(User userToApprove, Roles approverRole) {
        return Mono.fromCallable(() -> {
            ApprovalLevel requiredLevel = Optional.ofNullable(userToApprove.getApprovalLevel())
                    .orElse(ApprovalLevel.PENDING_L1); // default to L1 if not set

            log.debug("🔍 Validating approver role {} against required level {}",
                    approverRole, requiredLevel);

            boolean hasAuthority = switch (requiredLevel) {
                case PENDING_L1 ->
                    // Level 1 approval can be performed by Manager, Admin, or Super Admin
                        approverRole == Roles.MANAGER ||
                                approverRole == Roles.ADMIN ||
                                approverRole == Roles.SUPER_ADMIN;

                case PENDING_L2 ->
                    // Level 2 approval requires Admin or Super Admin
                        approverRole == Roles.ADMIN ||
                                approverRole == Roles.SUPER_ADMIN;

                case APPROVED_L1, APPROVED ->
                    // Already approved, no further action required
                        false;

                case NOT_REQUIRED ->
                    // No approval required
                        true;

                case REJECTED ->
                    // Rejected state cannot be approved
                        false;
            };

            log.debug("🔍 Authority validation result: {}", hasAuthority);
            return hasAuthority;
        });
    }


    /**
     * Perform full approval with role validation
     */
    private Mono<User> performApproval(
            User user,
            String approvedBy,
            Roles approverRole,
            Instant now
    ) {
        // Resolve permissions
        Set<String> permissions = permissionService.resolveEffectivePermissions(user);

        log.info("✅ Approving user {} with {} permissions",
                user.getEmail(), permissions.size());

        // Prepare permission data
        PermissionData permData = PermissionData.builder()
                .roles(new ArrayList<>(user.getRoleNames()))
                .permissions(new ArrayList<>(permissions))
                .status(UserStatus.ACTIVE)
                .approvedBy(approvedBy)
                .approvedAt(now)
                .build();

        // Update user
        user.setStatus(UserStatus.ACTIVE);
        user.setEnabled(true);
        user.setApprovedBy(approvedBy);
        user.setApprovedAt(now);
        user.setUpdatedAt(now);

        // Save atomically and notify
        return userRepository.saveUserWithPermissions(user, permData)
                .flatMap(savedUser ->
                        notificationService.notifyUserApproved(savedUser)
                                .thenReturn(savedUser))
                .doOnSuccess(approvedUser -> {
                    auditLogService.logApprovalAction(
                            user.getId(), approvedBy, "APPROVED", approverRole.name());

                    log.info("✅ User {} approved by {} ({}) at {}",
                            approvedUser.getEmail(), approvedBy, approverRole, now);
                });
    }

    /**
     * Perform simple approval without role validation
     */
    private Mono<Void> performSimpleApproval(User user, String performedById) {
        Instant now = clock.instant();

        // Resolve permissions
        Set<String> permissions = permissionService.resolveEffectivePermissions(user);

        log.info("✅ Simple approval for user {} with {} permissions",
                user.getEmail(), permissions.size());

        // Prepare permission data
        PermissionData permData = PermissionData.builder()
                .roles(new ArrayList<>(user.getRoleNames()))
                .permissions(new ArrayList<>(permissions))
                .status(UserStatus.ACTIVE)
                .approvedBy(performedById)
                .approvedAt(now)
                .build();

        // Update user
        user.setStatus(UserStatus.ACTIVE);
        user.setEnabled(true);
        user.setApprovedBy(performedById);
        user.setApprovedAt(now);
        user.setUpdatedAt(now);

        // Save and audit
        return userRepository.saveUserWithPermissions(user, permData)
                .doOnSuccess(v -> {
                    auditLogService.logApprovalAction(
                            user.getId(), performedById, "USER_APPROVAL", "");

                    log.info("✅ User {} approved (simple) by {} at {}",
                            user.getEmail(), performedById, now);
                })
                .then();
    }

    /**
     * Perform rejection with role validation
     */
    private Mono<Void> performRejection(
            User user,
            String rejectedBy,
            Roles rejectorRole,
            String reason,
            Instant now
    ) {
        log.info("❌ Rejecting user {} by {} ({}) - Reason: {}",
                user.getEmail(), rejectedBy, rejectorRole, reason);

        // Notify user before deletion
        return notificationService.notifyUserRejected(user, reason)
                .then(userRepository.delete(user.getId()))
                .then(deleteFromFirebaseAuth(user.getId(), user.getEmail(), now))
                .doOnSuccess(v -> {
                    auditLogService.logApprovalAction(
                            user.getId(), rejectedBy, "REJECTED", rejectorRole.name(), reason);

                    log.info("✅ User {} successfully rejected and deleted at {}",
                            user.getEmail(), now);
                });
    }

    /**
     * Perform simple rejection without role validation
     */
    private Mono<Void> performSimpleRejection(
            User user,
            String rejectedBy,
            String reason,
            Instant now
    ) {
        log.info("🗑️ Simple rejection for user {} - Reason: {}", user.getEmail(), reason);

        // Delete from Firestore and Firebase Auth
        return userRepository.delete(user.getId())
                .then(deleteFromFirebaseAuth(user.getId(), user.getEmail(), now))
                .doOnSuccess(v -> {
                    auditLogService.logApprovalAction(
                            user.getId(), rejectedBy, "REJECTED", "", reason);

                    log.info("✅ User {} deleted after rejection at {}", user.getEmail(), now);
                });
    }

    /**
     * Perform restoration of rejected user
     */
    private Mono<Void> performRestoration(User user, String restoredBy, Instant now) {
        log.info("♻️ Restoring rejected user {} by {} at {}",
                user.getEmail(), restoredBy, now);

        // Reset user to pending approval state
        user.setStatus(UserStatus.PENDING_APPROVAL);
        user.setAccountLocked(false);
        user.setEnabled(false);
        user.setUpdatedAt(now);

        // ✅ Store restoration metadata in attributes
        user.getAttributes().put("restoredBy", restoredBy);
        user.getAttributes().put("restoredAt", now.toString());

        // Track restoration count
        int currentCount = user.getAttributes().containsKey("restorationCount")
                ? ((Number) user.getAttributes().get("restorationCount")).intValue()
                : 0;
        user.getAttributes().put("restorationCount", currentCount + 1);

        return userRepository.update(user)
                .then(notificationService.notifyUserRestored(user))
                .doOnSuccess(v -> {
                    auditLogService.logApprovalAction(
                            user.getId(),
                            restoredBy,
                            String.valueOf(RESTORED),
                            "",
                            String.format("User reinstated after review (restoration #%d)",
                                    currentCount + 1)
                    );

                    log.info("✅ User {} restored and moved to PENDING_APPROVAL at {} (restoration #{})",
                            user.getEmail(), now, currentCount + 1);
                });
    }

    /**
     * Delete user from Firebase Auth
     */
    private Mono<Void> deleteFromFirebaseAuth(String userId, String email, Instant now) {
        return Mono.fromRunnable(() -> {
            try {
                firebaseAuth.deleteUser(userId);
                log.info("✅ Deleted user {} from Firebase Auth at {}", email, now);
            } catch (FirebaseAuthException e) {
                // Log but don't fail - Firestore deletion is primary
                if ("user-not-found".equals(e.getErrorCode())) {
                    log.warn("⚠️ User {} already deleted from Firebase Auth", email);
                } else {
                    log.error("⚠️ Failed to delete user {} from Firebase Auth: {}",
                            email, e.getMessage());
                }
            }
        });
    }
}