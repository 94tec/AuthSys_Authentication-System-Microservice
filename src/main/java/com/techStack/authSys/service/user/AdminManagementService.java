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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AdminManagementService {
    private static final Logger log = LoggerFactory.getLogger(AdminManagementService.class);

    private final Firestore firestore;
    private final FirebaseAuth firebaseAuth;
    private final AuditLogService auditLogService;
    private final RateLimiterService.SessionService sessionService;
    private final PermissionProvider permissionProvider;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final AdminNotificationService adminNotificationService;

    private static final String USERS_COLLECTION = "users";
    private static final String USER_PERMISSIONS_COLLECTION = "user_permissions";

    private String maskSensitive(String value, String type) {
        if (value == null) return null;
        return switch (type) {
            case "email" -> value.replaceAll("(?<=.).(?=[^@]*?.@)", "*");
            case "ip" -> value.replaceAll("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b", "$1.***.***.$4");
            case "device" -> value.length() > 4 ? STR."\{value.substring(0, 2)}***\{value.substring(value.length() - 2)}" : "***";
            default -> "***";
        };
    }

    public Mono<Void> approvePendingUser(String userId, String performedById) {
        return getUser(userId)
                .flatMap(user -> {
                    // Validate if user is in pending state
                    if (user.getStatus() != User.Status.PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException(
                                "User must be in PENDING_APPROVAL status for approval. Current status: " + user.getStatus()));
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

    public Mono<Void> approveAndAssignRole(User user, String performedById) {
        return Mono.just(user)
                .flatMap(u -> {
                    // Validate input and state
                    if (u.getStatus() == User.Status.ACTIVE && u.getRoleNames() != null) {
                        return Mono.error(new IllegalStateException(
                                "User already has active status and roles assigned"));
                    }

                    return approveAndUpdateUser(u, performedById);
                });
    }

    private Mono<Void> approveAndUpdateUser(User user, String performedById) {
        return Mono.defer(() -> {
            user.setStatus(User.Status.ACTIVE);
            Instant approvalTime = Instant.now();

            Set<String> permissions = permissionProvider.resolveEffectivePermissions(user);

            UserPermissions userPermissions = UserPermissions.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .roles(new ArrayList<>(user.getRoleNames()))
                    .permissions(new ArrayList<>(permissions))
                    .status(User.Status.ACTIVE)
                    .approvedAt(approvalTime)
                    .approvedBy(performedById)
                    .build();

            return executeApprovalTransaction(user, userPermissions)
                    .then(logStatusChange(
                            user.getId(),
                            performedById,
                            "USER_APPROVAL",
                            Map.of(
                                    "status", "ACTIVE",
                                    "roles", user.getRoleNames(),
                                    "permissionsCount", permissions.size()
                            )
                    ));
        });
    }
    
    private Mono<User> getUser(String userId) {
        DocumentReference docRef = firestore.collection(USERS_COLLECTION).document(userId);
        ApiFuture<DocumentSnapshot> future = docRef.get();

        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(future))
                .map(snapshot -> {
                    if (snapshot.exists()) {
                        User user = snapshot.toObject(User.class);
                        user.setId(snapshot.getId()); // optional
                        return user;
                    } else {
                        throw new RuntimeException("User not found with ID: " + userId);
                    }
                });
    }

    private Mono<Void> executeApprovalTransaction(User user, UserPermissions permissions) {
        return Mono.fromCallable(() -> {
                    WriteBatch batch = firestore.batch();

                    // Update user document
                    DocumentReference userRef = firestore.collection(USERS_COLLECTION).document(user.getId());
                    batch.update(userRef,
                            "status", User.Status.ACTIVE.name(),
                            "roles", new ArrayList<>(user.getRoleNames()),
                            "lastModified", FieldValue.serverTimestamp()
                    );

                    // Set permissions document
                    DocumentReference permRef = userRef
                            .collection(USERS_COLLECTION)
                            .document(user.getId())
                            .collection(USER_PERMISSIONS_COLLECTION)
                            .document("default");

                    batch.set(permRef, permissions);


                    return batch.commit();
                })
                .flatMap(commitFuture -> Mono.fromFuture(() ->
                        FirestoreUtil.toCompletableFuture(commitFuture)))
                .then();
    }
    /**
     * Approve user account - Enhanced with approval level validation
     */
    public Mono<User> approveUserAccount(String userId, String approvedBy, Roles approverRole) {
        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    // Validate user is pending approval
                    if (user.getStatus() != User.Status.PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException(
                                "User " + user.getEmail() + " is not pending approval. Current status: " + user.getStatus()));
                    }

                    // Validate approver has sufficient privileges
                    return validateApproverAuthority(user, approverRole)
                            .flatMap(hasAuthority -> {
                                if (!hasAuthority) {
                                    auditLogService.logUnauthorizedApproval(userId, approvedBy, approverRole.name());
                                    return Mono.error(new SecurityException(
                                            "Approver role " + approverRole + " insufficient to approve user with roles " + user.getRoles()));
                                }

                                // Approve user
                                user.setStatus(User.Status.ACTIVE);
                                user.setEnabled(true);
                                user.setCreatedBy(approvedBy);
                                user.setApprovedAt(Instant.now());
                                user.setApprovedBy(approvedBy);

                                log.info("✅ User {} approved by {} ({})", user.getEmail(), approvedBy, approverRole);

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
                    log.error("❌ Failed to approve user {}: {}", userId, e.getMessage());
                    return Mono.error(e);
                });
    }
    /**
     * Validate if approver has authority to approve user
     * Implements hierarchical approval logic
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
     * Reject user account - Enhanced with reason tracking
     */
    public Mono<Void> rejectUserAccount(String userId, String rejectedBy, Roles rejectorRole, String reason) {
        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != User.Status.PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException("User is not pending approval"));
                    }

                    // Validate rejector has authority
                    return validateApproverAuthority(user, rejectorRole)
                            .flatMap(hasAuthority -> {
                                if (!hasAuthority) {
                                    return Mono.error(new SecurityException(
                                            "Rejector role " + rejectorRole + " insufficient to reject user"));
                                }

                                log.info("❌ Rejecting user {} by {} ({}) - Reason: {}",
                                        user.getEmail(), rejectedBy, rejectorRole, reason);

                                // Notify user before deletion
                                return adminNotificationService.notifyUserRejected(user, reason)
                                        .then(firebaseServiceAuth.deleteUser(user.getId())
                                                .then(Mono.fromRunnable(() -> {
                                                    try {
                                                        firebaseAuth.deleteUser(user.getId());
                                                        log.info("✅ Deleted rejected user {} from Firebase Auth", user.getEmail());
                                                    } catch (Exception e) {
                                                        log.error("⚠️ Failed to delete user from Firebase Auth: {}", e.getMessage());
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
     * Reject a pending user account
     */
    public Mono<Void> rejectUserAccount(String userId, String rejectedBy, String reason) {
        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != User.Status.PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException(
                                "User is not pending approval"));
                    }

                    log.info("❌ Rejecting user {} by {} - Reason: {}",
                            user.getEmail(), rejectedBy, reason);

                    // Delete user from Firestore and Firebase Auth
                    return firebaseServiceAuth.deleteUser(user.getId())
                            .then(Mono.fromRunnable(() -> {
                                try {
                                    firebaseAuth.deleteUser(user.getId());
                                    log.info("✅ Deleted rejected user {} from Firebase Auth", user.getEmail());
                                } catch (Exception e) {
                                    log.error("⚠️ Failed to delete user from Firebase Auth: {}", e.getMessage());
                                }
                            }));

                });
    }
    /**
     * Restores a previously rejected user.
     * - Only SUPER_ADMIN (or authorized approver) can perform this.
     * - Sets status back to PENDING_APPROVAL (or ACTIVE based on role rules).
     * - Keeps audit and rejection history.
     */
    public Mono<Void> restoreRejectedUser(String userId, String restoredBy, Roles restorerRole) {
        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != User.Status.REJECTED) {
                        return Mono.error(new IllegalStateException("User is not in REJECTED status"));
                    }

                    // Validate authority of restorer
                    return validateApproverAuthority(user, restorerRole)
                            .flatMap(hasAuthority -> {
                                if (!hasAuthority) {
                                    return Mono.error(new SecurityException(
                                            "Role " + restorerRole + " insufficient to restore user account"));
                                }

                                log.info("♻️ Restoring rejected user {} by {} ({})",
                                        user.getEmail(), restoredBy, restorerRole);

                                // Reactivate account
                                user.setStatus(User.Status.PENDING_APPROVAL);
                                user.setAccountLocked(false);
                                user.setEnabled(false); // still inactive until approval
                                user.setRestoredBy(restoredBy);
                                user.setRestoredAt(Instant.now().toString());

                                return firebaseServiceAuth.updateUserInFirestore(user)
                                        .then(adminNotificationService.notifyUserRestored(user))
                                        .then(Mono.fromRunnable(() ->
                                                auditLogService.logApprovalAction(
                                                        userId, restoredBy, "RESTORED", restorerRole.name(),
                                                        "User reinstated after review")))
                                        .doOnSuccess(v ->
                                                log.info("✅ User {} restored and moved to PENDING_APPROVAL", user.getEmail()))
                                        .doOnError(e ->
                                                log.error("❌ Failed to restore user {}: {}", user.getEmail(), e.getMessage()))
                                        .then();
                            });
                })
                .onErrorResume(e -> {
                    log.error("⚠️ Error restoring user {}: {}", userId, e.getMessage(), e);
                    return Mono.error(e);
                });
    }


    // Example implementation - adapt to your security context
    private String getCurrentAdminId() {
        return SecurityContextHolder.getContext()
                .getAuthentication()
                .getName(); // Or custom claims from token if available
    }

    public Mono<Void> rejectPendingUser(String userId, String performedById) {
        return updateUserStatus(userId, User.Status.REJECTED)
                .then(logStatusChange(userId, performedById, "REJECT_PENDING_USER", Map.of("from", "PENDING", "to", "REJECTED")));
    }

    public Mono<Void> suspendUser(String userId, String performedById) {
        return updateUserStatus(userId, User.Status.SUSPENDED)
                .then(sessionService.invalidateUserSessions(userId))
                .then(logStatusChange(userId, performedById, "SUSPEND_ACCOUNT", Map.of("status", "SUSPENDED")));
    }

    public Mono<Void> reactivateUser(String userId, String performedById) {
        return updateUserStatus(userId, User.Status.ACTIVE)
                .then(logStatusChange(userId, performedById, "REACTIVATE_ACCOUNT", Map.of("status", "ACTIVE")));
    }

    private Mono<Void> updateUserStatus(String userId, User.Status newStatus) {
        ApiFuture<WriteResult> future = firestore.collection(USERS_COLLECTION)
                .document(userId)
                .update("status", newStatus.name());

        return FirestoreUtils.apiFutureToMono(future).then();
    }

    private Mono<Void> logStatusChange(String userId, String performedById,
                                       String actionType, Map<String, Object> metadata) {
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
    public Mono<Void> initiateForcedPasswordReset(String userId, @Nullable String ipAddress) {
        // 1. Update Firestore flag
        Mono<Void> firestoreUpdate = Mono.fromFuture(
                FirestoreUtil.toCompletableFuture(
                        firestore.collection(USERS_COLLECTION)
                                .document(userId)
                                .update("forcePasswordReset", true)
                )
        ).then();

        // 2. Invalidate sessions (by IP if given, otherwise all)
        Mono<Void> invalidateSessions = (ipAddress != null)
                ? sessionService.invalidateSession(userId, ipAddress)
                : sessionService.invalidateAllSessionsForUser(userId);

        // 3. Audit log
        AuditEventLog event = AuditEventLog.forUserAction(
                "FORCED_PASSWORD_RESET",
                userId,
                "System",
                Map.of("trigger", "admin_action")
        );
        Mono<Void> auditLog = auditLogService.logEventLog(event);

        return firestoreUpdate
                .then(invalidateSessions)
                .then(auditLog);
    }

    public Flux<User> findUsersWithFilters(Optional<String> role, Optional<String> status, Optional<String> email,
                                           Optional<Instant> createdAfter, Optional<Instant> createdBefore) {

        CollectionReference usersRef = firestore.collection(USERS_COLLECTION);
        Query query = usersRef;

        if (role.isPresent()) query = query.whereEqualTo("role", role.get());
        if (status.isPresent()) query = query.whereEqualTo("status", status.get());
        if (email.isPresent()) query = query.whereEqualTo("email", email.get());
        if (createdAfter.isPresent()) query = query.whereGreaterThanOrEqualTo("createdAt", createdAfter.get());
        if (createdBefore.isPresent()) query = query.whereLessThanOrEqualTo("createdAt", createdBefore.get());

        ApiFuture<QuerySnapshot> queryFuture = query.get();

        return FirestoreUtils.apiFutureToMono(queryFuture)
                .flatMapMany(snapshot -> Flux.fromIterable(snapshot.getDocuments()))
                .map(doc -> doc.toObject(User.class));
    }
    public Flux<SessionRecord> getLoginHistory(String userId,
                                               Optional<String> ipAddress,
                                               Optional<String> device,
                                               Optional<Instant> after,
                                               Optional<Instant> before) {
        CollectionReference sessionsRef = firestore.collection("sessions");
        Query query = sessionsRef.whereEqualTo("userId", userId);

        if (ipAddress.isPresent()) {
            query = query.whereEqualTo("ipAddress", ipAddress.get());
        }
        if (device.isPresent()) {
            query = query.whereEqualTo("device", device.get());
        }
        if (after.isPresent()) {
            query = query.whereGreaterThanOrEqualTo("loginTime", Timestamp.ofTimeSecondsAndNanos(after.get().getEpochSecond(), 0));
        }
        if (before.isPresent()) {
            query = query.whereLessThanOrEqualTo("loginTime", Timestamp.ofTimeSecondsAndNanos(before.get().getEpochSecond(), 0));
        }

        return FirestoreUtils.apiFutureToMono(query.get())
                .flatMapMany(snapshot -> Flux.fromIterable(snapshot.getDocuments()))
                .map(doc -> doc.toObject(SessionRecord.class));
    }


}
