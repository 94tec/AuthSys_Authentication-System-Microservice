package com.techStack.authSys.service.user;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuth;
import com.techStack.authSys.dto.internal.SessionRecord;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.audit.AuditEventLog;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserPermissions;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.repository.sucurity.RateLimiterService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import com.techStack.authSys.util.firebase.FirestoreUtils;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.*;

import static com.techStack.authSys.constants.SecurityConstants.COLLECTION_USERS;
import static com.techStack.authSys.constants.SecurityConstants.COLLECTION_USER_PERMISSIONS;
import static com.techStack.authSys.models.user.UserStatus.*;

/**
 * Admin Management Service
 *
 * Handles administrative operations for user management.
 * Uses Clock for all timestamp operations.
 */
@Service
@RequiredArgsConstructor
public class AdminManagementService {

    private static final Logger log = LoggerFactory.getLogger(AdminManagementService.class);

    /* =========================
       Dependencies
       ========================= */

    private final Firestore firestore;
    private final FirebaseAuth firebaseAuth;
    private final AuditLogService auditLogService;
    private final RateLimiterService.SessionService sessionService;
    private final PermissionProvider permissionProvider;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final AdminNotificationService adminNotificationService;
    private final Clock clock;

    /* =========================
       User Approval
       ========================= */

    /**
     * Approve pending user
     */
    public Mono<Void> approvePendingUser(String userId, String performedById) {
        return getUser(userId)
                .flatMap(user -> {
                    // Validate if user is in pending state
                    if (user.getStatus() != PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException(
                                "User must be in PENDING_APPROVAL status for approval. Current status: " +
                                        user.getStatus()));
                    }

                    return approveAndUpdateUser(user, performedById);
                })
                .onErrorResume(e -> {
                    log.error("Failed to approve user {}: {}", userId, e.getMessage());

                    User minimalUser = new User();
                    minimalUser.setId(userId);

                    auditLogService.logAudit(
                            minimalUser,
                            ActionType.USER_APPROVAL_FAILED,
                            "Failed to approve user: " + e.getMessage(),
                            "internal"
                    );

                    return Mono.error(e);
                });
    }

    /**
     * Approve and assign role
     */
    public Mono<Void> approveAndAssignRole(User user, String performedById) {
        return Mono.just(user)
                .flatMap(u -> {
                    // Validate input and state
                    if (u.getStatus() == ACTIVE && u.getRoleNames() != null) {
                        return Mono.error(new IllegalStateException(
                                "User already has active status and roles assigned"));
                    }

                    return approveAndUpdateUser(u, performedById);
                });
    }

    /**
     * Approve and update user
     */
    private Mono<Void> approveAndUpdateUser(User user, String performedById) {
        Instant now = clock.instant();

        return Mono.defer(() -> {
            user.setStatus(ACTIVE);

            Set<String> permissions = permissionProvider.resolveEffectivePermissions(user);

            UserPermissions userPermissions = UserPermissions.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .roles(new ArrayList<>(user.getRoleNames()))
                    .permissions(new ArrayList<>(permissions))
                    .status(ACTIVE)
                    .approvedAt(now)
                    .approvedBy(performedById)
                    .build();

            return executeApprovalTransaction(user, userPermissions, now)
                    .then(logStatusChange(
                            user.getId(),
                            performedById,
                            "USER_APPROVAL",
                            Map.of(
                                    "status", "ACTIVE",
                                    "roles", user.getRoleNames(),
                                    "permissionsCount", permissions.size(),
                                    "timestamp", now
                            )
                    ));
        });
    }

    /**
     * Approve user account with role validation
     */
    public Mono<User> approveUserAccount(String userId, String approvedBy, Roles approverRole) {
        Instant now = clock.instant();

        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    // Validate user is pending approval
                    if (user.getStatus() != PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException(
                                "User " + user.getEmail() + " is not pending approval. Current status: " +
                                        user.getStatus()));
                    }

                    // Validate approver has sufficient privileges
                    return validateApproverAuthority(user, approverRole)
                            .flatMap(hasAuthority -> {
                                if (!hasAuthority) {
                                    auditLogService.logUnauthorizedApproval(userId, approvedBy, approverRole.name());
                                    return Mono.error(new SecurityException(
                                            "Approver role " + approverRole +
                                                    " insufficient to approve user with roles " + user.getRoles()));
                                }

                                // Approve user
                                user.setStatus(ACTIVE);
                                user.setEnabled(true);
                                user.setCreatedBy(approvedBy);
                                user.setApprovedAt(now);
                                user.setApprovedBy(approvedBy);

                                log.info("✅ User {} approved by {} ({}) at {}",
                                        user.getEmail(), approvedBy, approverRole, now);

                                // Save and notify
                                return firebaseServiceAuth.save(user)
                                        .flatMap(approvedUser ->
                                                adminNotificationService.notifyUserApproved(approvedUser)
                                                        .thenReturn(approvedUser))
                                        .doOnSuccess(approvedUser -> {
                                            auditLogService.logApprovalAction(
                                                    userId, approvedBy, "APPROVED", approverRole.name());
                                        });
                            });
                })
                .onErrorResume(e -> {
                    log.error("❌ Failed to approve user {} at {}: {}", userId, now, e.getMessage());
                    return Mono.error(e);
                });
    }

    /* =========================
       User Rejection
       ========================= */

    /**
     * Reject user account with reason
     */
    public Mono<Void> rejectUserAccount(
            String userId,
            String rejectedBy,
            Roles rejectorRole,
            String reason
    ) {
        Instant now = clock.instant();

        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException("User is not pending approval"));
                    }

                    // Validate rejector has authority
                    return validateApproverAuthority(user, rejectorRole)
                            .flatMap(hasAuthority -> {
                                if (!hasAuthority) {
                                    return Mono.error(new SecurityException(
                                            "Rejector role " + rejectorRole +
                                                    " insufficient to reject user"));
                                }

                                log.info("❌ Rejecting user {} by {} ({}) at {} - Reason: {}",
                                        user.getEmail(), rejectedBy, rejectorRole, now, reason);

                                // Notify user before deletion
                                return adminNotificationService.notifyUserRejected(user, reason)
                                        .then(firebaseServiceAuth.deleteUser(user.getId())
                                                .then(Mono.fromRunnable(() -> {
                                                    try {
                                                        firebaseAuth.deleteUser(user.getId());
                                                        log.info("✅ Deleted rejected user {} from Firebase Auth at {}",
                                                                user.getEmail(), now);
                                                    } catch (Exception e) {
                                                        log.error("⚠️ Failed to delete user from Firebase Auth: {}",
                                                                e.getMessage());
                                                    }
                                                }))
                                                .doOnSuccess(v -> {
                                                    auditLogService.logApprovalAction(
                                                            userId, rejectedBy, "REJECTED", rejectorRole.name(), reason);
                                                }));
                            });
                }).then();
    }

    /**
     * Reject user account (simple version)
     */
    public Mono<Void> rejectUserAccount(String userId, String rejectedBy, String reason) {
        Instant now = clock.instant();

        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException("User is not pending approval"));
                    }

                    log.info("❌ Rejecting user {} by {} at {} - Reason: {}",
                            user.getEmail(), rejectedBy, now, reason);

                    // Delete user from Firestore and Firebase Auth
                    return firebaseServiceAuth.deleteUser(user.getId())
                            .then(Mono.fromRunnable(() -> {
                                try {
                                    firebaseAuth.deleteUser(user.getId());
                                    log.info("✅ Deleted rejected user {} from Firebase Auth at {}",
                                            user.getEmail(), now);
                                } catch (Exception e) {
                                    log.error("⚠️ Failed to delete user from Firebase Auth: {}",
                                            e.getMessage());
                                }
                            }));
                });
    }

    /**
     * Reject pending user
     */
    public Mono<Void> rejectPendingUser(String userId, String performedById) {
        Instant now = clock.instant();

        return updateUserStatus(userId, REJECTED, now)
                .then(logStatusChange(
                        userId,
                        performedById,
                        "REJECT_PENDING_USER",
                        Map.of(
                                "from", "PENDING",
                                "to", "REJECTED",
                                "timestamp", now
                        )
                ));
    }

    /* =========================
       User Restoration
       ========================= */

    /**
     * Restore rejected user
     */
    public Mono<Void> restoreRejectedUser(String userId, String restoredBy, Roles restorerRole) {
        Instant now = clock.instant();

        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != REJECTED) {
                        return Mono.error(new IllegalStateException("User is not in REJECTED status"));
                    }

                    // Validate authority of restorer
                    return validateApproverAuthority(user, restorerRole)
                            .flatMap(hasAuthority -> {
                                if (!hasAuthority) {
                                    return Mono.error(new SecurityException(
                                            "Role " + restorerRole + " insufficient to restore user account"));
                                }

                                log.info("♻️ Restoring rejected user {} by {} ({}) at {}",
                                        user.getEmail(), restoredBy, restorerRole, now);

                                // Reactivate account
                                user.setStatus(PENDING_APPROVAL);
                                user.setAccountLocked(false);
                                user.setEnabled(false);
                                user.setRestoredBy(restoredBy);
                                user.setRestoredAt(now.toString());

                                return firebaseServiceAuth.updateUserInFirestore(user)
                                        .then(adminNotificationService.notifyUserRestored(user))
                                        .then(Mono.fromRunnable(() ->
                                                auditLogService.logApprovalAction(
                                                        userId, restoredBy, "RESTORED", restorerRole.name(),
                                                        "User reinstated after review")))
                                        .doOnSuccess(v ->
                                                log.info("✅ User {} restored and moved to PENDING_APPROVAL at {}",
                                                        user.getEmail(), now))
                                        .doOnError(e ->
                                                log.error("❌ Failed to restore user {} at {}: {}",
                                                        user.getEmail(), now, e.getMessage()))
                                        .then();
                            });
                })
                .onErrorResume(e -> {
                    log.error("⚠️ Error restoring user {} at {}: {}", userId, now, e.getMessage(), e);
                    return Mono.error(e);
                });
    }

    /* =========================
       User Management
       ========================= */

    /**
     * Suspend user
     */
    public Mono<Void> suspendUser(String userId, String performedById) {
        Instant now = clock.instant();

        return updateUserStatus(userId, SUSPENDED, now)
                .then(sessionService.invalidateUserSessions(userId))
                .then(logStatusChange(
                        userId,
                        performedById,
                        "SUSPEND_ACCOUNT",
                        Map.of(
                                "status", "SUSPENDED",
                                "timestamp", now
                        )
                ));
    }

    /**
     * Reactivate user
     */
    public Mono<Void> reactivateUser(String userId, String performedById) {
        Instant now = clock.instant();

        return updateUserStatus(userId, ACTIVE, now)
                .then(logStatusChange(
                        userId,
                        performedById,
                        "REACTIVATE_ACCOUNT",
                        Map.of(
                                "status", "ACTIVE",
                                "timestamp", now
                        )
                ));
    }

    /**
     * Initiate forced password reset
     */
    public Mono<Void> initiateForcedPasswordReset(String userId, @Nullable String ipAddress) {
        Instant now = clock.instant();

        // 1. Update Firestore flag
        Mono<Void> firestoreUpdate = Mono.fromFuture(
                FirestoreUtil.toCompletableFuture(
                        firestore.collection(COLLECTION_USERS)
                                .document(userId)
                                .update(
                                        "forcePasswordReset", true,
                                        "updatedAt", now
                                )
                )
        ).then();

        // 2. Invalidate sessions
        Mono<Void> invalidateSessions = (ipAddress != null)
                ? sessionService.invalidateSession(userId, ipAddress)
                : sessionService.invalidateAllSessionsForUser(userId);

        // 3. Audit log
        AuditEventLog event = AuditEventLog.forUserAction(
                "FORCED_PASSWORD_RESET",
                userId,
                "System",
                Map.of(
                        "trigger", "admin_action",
                        "timestamp", now
                )
        );
        Mono<Void> auditLog = auditLogService.logEventLog(event);

        return firestoreUpdate
                .then(invalidateSessions)
                .then(auditLog);
    }

    /* =========================
       User Queries
       ========================= */

    /**
     * Find users with filters
     */
    public Flux<User> findUsersWithFilters(
            Optional<String> role,
            Optional<String> status,
            Optional<String> email,
            Optional<Instant> createdAfter,
            Optional<Instant> createdBefore
    ) {
        CollectionReference usersRef = firestore.collection(COLLECTION_USERS);
        Query query = usersRef;

        if (role.isPresent()) query = query.whereEqualTo("role", role.get());
        if (status.isPresent()) query = query.whereEqualTo("status", status.get());
        if (email.isPresent()) query = query.whereEqualTo("email", email.get());
        if (createdAfter.isPresent())
            query = query.whereGreaterThanOrEqualTo("createdAt", createdAfter.get());
        if (createdBefore.isPresent())
            query = query.whereLessThanOrEqualTo("createdAt", createdBefore.get());

        ApiFuture<QuerySnapshot> queryFuture = query.get();

        return FirestoreUtils.apiFutureToMono(queryFuture)
                .flatMapMany(snapshot -> Flux.fromIterable(snapshot.getDocuments()))
                .map(doc -> doc.toObject(User.class));
    }

    /**
     * Get login history
     */
    public Flux<SessionRecord> getLoginHistory(
            String userId,
            Optional<String> ipAddress,
            Optional<String> device,
            Optional<Instant> after,
            Optional<Instant> before
    ) {
        CollectionReference sessionsRef = firestore.collection("sessions");
        Query query = sessionsRef.whereEqualTo("userId", userId);

        if (ipAddress.isPresent()) {
            query = query.whereEqualTo("ipAddress", ipAddress.get());
        }
        if (device.isPresent()) {
            query = query.whereEqualTo("device", device.get());
        }
        if (after.isPresent()) {
            query = query.whereGreaterThanOrEqualTo(
                    "loginTime",
                    Timestamp.ofTimeSecondsAndNanos(after.get().getEpochSecond(), 0)
            );
        }
        if (before.isPresent()) {
            query = query.whereLessThanOrEqualTo(
                    "loginTime",
                    Timestamp.ofTimeSecondsAndNanos(before.get().getEpochSecond(), 0)
            );
        }

        return FirestoreUtils.apiFutureToMono(query.get())
                .flatMapMany(snapshot -> Flux.fromIterable(snapshot.getDocuments()))
                .map(doc -> doc.toObject(SessionRecord.class));
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Get user by ID
     */
    private Mono<User> getUser(String userId) {
        DocumentReference docRef = firestore.collection(COLLECTION_USERS).document(userId);
        ApiFuture<DocumentSnapshot> future = docRef.get();

        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(future))
                .map(snapshot -> {
                    if (snapshot.exists()) {
                        User user = snapshot.toObject(User.class);
                        user.setId(snapshot.getId());
                        return user;
                    } else {
                        throw new RuntimeException("User not found with ID: " + userId);
                    }
                });
    }

    /**
     * Execute approval transaction
     */
    private Mono<Void> executeApprovalTransaction(
            User user,
            UserPermissions permissions,
            Instant now
    ) {
        return Mono.fromCallable(() -> {
                    WriteBatch batch = firestore.batch();

                    // Update user document
                    DocumentReference userRef = firestore.collection(COLLECTION_USERS).document(user.getId());
                    batch.update(userRef,
                            "status", ACTIVE.name(),
                            "roles", new ArrayList<>(user.getRoleNames()),
                            "updatedAt", now
                    );

                    // Set permissions document
                    DocumentReference permRef = userRef
                            .collection(COLLECTION_USER_PERMISSIONS)
                            .document("default");

                    batch.set(permRef, permissions);

                    return batch.commit();
                })
                .flatMap(commitFuture -> Mono.fromFuture(() ->
                        FirestoreUtil.toCompletableFuture(commitFuture)))
                .then();
    }

    /**
     * Validate approver authority
     */
    private Mono<Boolean> validateApproverAuthority(User userToApprove, Roles approverRole) {
        return Mono.fromCallable(() -> {
            RoleAssignmentService.ApprovalLevel requiredLevel = userToApprove.getApprovalLevel()
                    .orElse(RoleAssignmentService.ApprovalLevel.MANAGER_OR_ABOVE);

            switch (requiredLevel) {
                case SUPER_ADMIN_ONLY:
                    return approverRole == Roles.SUPER_ADMIN;

                case ADMIN_OR_SUPER_ADMIN:
                    return approverRole == Roles.SUPER_ADMIN || approverRole == Roles.ADMIN;

                case MANAGER_OR_ABOVE:
                    return approverRole == Roles.SUPER_ADMIN ||
                            approverRole == Roles.ADMIN ||
                            approverRole == Roles.MANAGER;

                default:
                    return false;
            }
        });
    }

    /**
     * Update user status
     */
    private Mono<Void> updateUserStatus(String userId, UserStatus newStatus, Instant now) {
        ApiFuture<WriteResult> future = firestore.collection(COLLECTION_USERS)
                .document(userId)
                .update(
                        "status", newStatus.name(),
                        "updatedAt", now
                );

        return FirestoreUtils.apiFutureToMono(future).then();
    }

    /**
     * Log status change
     */
    private Mono<Void> logStatusChange(
            String userId,
            String performedById,
            String actionType,
            Map<String, Object> metadata
    ) {
        AuditEventLog event = AuditEventLog.forUserAction(
                actionType,
                userId,
                performedById,
                metadata
        );

        return Mono.fromRunnable(() -> {
                    auditLogService.logEventLog(event);
                    log.info("{} completed for user {} by {}", actionType, userId, performedById);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Get current admin ID
     */
    private String getCurrentAdminId() {
        return SecurityContextHolder.getContext()
                .getAuthentication()
                .getName();
    }

    /**
     * Mask sensitive data
     */
    private String maskSensitive(String value, String type) {
        if (value == null) return null;

        return switch (type) {
            case "email" -> value.replaceAll("(?<=.).(?=[^@]*?.@)", "*");
            case "ip" -> value.replaceAll("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b",
                    "$1.***.***.$4");
            case "device" -> value.length() > 4 ?
                    value.substring(0, 2) + "***" + value.substring(value.length() - 2) : "***";
            default -> "***";
        };
    }
}