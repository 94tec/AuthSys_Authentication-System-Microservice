package com.techStack.authSys.service;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.techStack.authSys.dto.SessionRecord;
import com.techStack.authSys.models.*;
import com.techStack.authSys.repository.PermissionProvider;
import com.techStack.authSys.repository.RateLimiterService;
import com.techStack.authSys.util.FirestoreUtil;
import com.techStack.authSys.util.FirestoreUtils;
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
    private final AuditLogService auditLogService;
    private final RateLimiterService.SessionService sessionService;
    private final PermissionProvider permissionProvider;

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
