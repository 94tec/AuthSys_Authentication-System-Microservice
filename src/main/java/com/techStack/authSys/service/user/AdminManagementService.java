package com.techStack.authSys.service.user;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.techStack.authSys.dto.internal.SessionRecord;
import com.techStack.authSys.models.audit.AuditEventLog;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.firebase.FirestoreUtils;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static com.techStack.authSys.constants.SecurityConstants.COLLECTION_USERS;

/**
 * Admin Management Service (Refactored)
 *
 * Single Responsibility: User lifecycle management operations
 *
 * Responsibilities:
 * - Suspend/reactivate users
 * - Force password resets
 * - Query users with filters
 * - Get login history
 *
 * Does NOT:
 * - Approve/reject users (moved to UserApprovalService)
 * - Manage passwords (that's UserService)
 * - Handle registration (that's UserRegistrationOrchestrator)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminManagementService {

    /* =========================
       Dependencies
       ========================= */

    private final FirestoreUserRepository userRepository;  // ✅ Use repository pattern
    private final Firestore firestore;  // For queries only
    private final AuditLogService auditLogService;
    private final SessionService sessionService;
    private final Clock clock;

    /* =========================
       User Lifecycle Management
       ========================= */

    /**
     * Suspend user account and invalidate all sessions
     *
     * @param userId User to suspend
     * @param performedById Admin performing the action
     */
    public Mono<Void> suspendUser(String userId, String performedById) {
        Instant now = clock.instant();

        log.info("🔒 Suspending user {} by {} at {}", userId, performedById, now);

        return userRepository.findById(userId)
                .flatMap(user -> {
                    // Update user status
                    user.setStatus(UserStatus.SUSPENDED);
                    user.setEnabled(false);
                    user.setUpdatedAt(now);

                    return userRepository.update(user)
                            .then(sessionService.invalidateUserSessions(userId))
                            .then(logStatusChange(
                                    userId,
                                    performedById,
                                    "SUSPEND_ACCOUNT",
                                    Map.of(
                                            "status", "SUSPENDED",
                                            "timestamp", now
                                    )
                            ))
                            .doOnSuccess(v ->
                                    log.info("✅ User {} suspended successfully at {}",
                                            user.getEmail(), now))
                            .doOnError(e ->
                                    log.error("❌ Failed to suspend user {}: {}",
                                            user.getEmail(), e.getMessage()));
                });
    }

    /**
     * Reactivate suspended user account
     *
     * @param userId User to reactivate
     * @param performedById Admin performing the action
     */
    public Mono<Void> reactivateUser(String userId, String performedById) {
        Instant now = clock.instant();

        log.info("🔓 Reactivating user {} by {} at {}", userId, performedById, now);

        return userRepository.findById(userId)
                .flatMap(user -> {
                    // Validate user can be reactivated
                    if (user.getStatus() != UserStatus.SUSPENDED) {
                        log.warn("⚠️ Cannot reactivate user {} - current status: {}",
                                user.getEmail(), user.getStatus());

                        return Mono.error(new IllegalStateException(
                                "User is not suspended. Current status: " + user.getStatus()));
                    }

                    // Update user status
                    user.setStatus(UserStatus.ACTIVE);
                    user.setEnabled(true);
                    user.setUpdatedAt(now);

                    return userRepository.update(user)
                            .then(logStatusChange(
                                    userId,
                                    performedById,
                                    "REACTIVATE_ACCOUNT",
                                    Map.of(
                                            "status", "ACTIVE",
                                            "timestamp", now
                                    )
                            ))
                            .doOnSuccess(v ->
                                    log.info("✅ User {} reactivated successfully at {}",
                                            user.getEmail(), now))
                            .doOnError(e ->
                                    log.error("❌ Failed to reactivate user {}: {}",
                                            user.getEmail(), e.getMessage()));
                });
    }

    /**
     * Lock user account (prevents login)
     *
     * @param userId User to lock
     * @param performedById Admin performing the action
     * @param reason Reason for locking
     */
    public Mono<Void> lockUserAccount(String userId, String performedById, String reason) {
        Instant now = clock.instant();

        log.info("🔐 Locking user {} by {} - Reason: {}", userId, performedById, reason);

        return userRepository.findById(userId)
                .flatMap(user -> {
                    user.setAccountLocked(true);
                    user.setEnabled(false);
                    user.setUpdatedAt(now);

                    return userRepository.update(user)
                            .then(sessionService.invalidateUserSessions(userId))
                            .then(logStatusChange(
                                    userId,
                                    performedById,
                                    "LOCK_ACCOUNT",
                                    Map.of(
                                            "reason", reason,
                                            "timestamp", now
                                    )
                            ))
                            .doOnSuccess(v ->
                                    log.info("✅ User {} locked successfully", user.getEmail()));
                });
    }

    /**
     * Unlock user account
     *
     * @param userId User to unlock
     * @param performedById Admin performing the action
     */
    public Mono<Void> unlockUserAccount(String userId, String performedById) {
        Instant now = clock.instant();

        log.info("🔓 Unlocking user {} by {}", userId, performedById);

        return userRepository.findById(userId)
                .flatMap(user -> {
                    user.setAccountLocked(false);
                    user.setEnabled(true);
                    user.setFailedLoginAttempts(0);  // Reset failed attempts
                    user.setUpdatedAt(now);

                    return userRepository.update(user)
                            .then(logStatusChange(
                                    userId,
                                    performedById,
                                    "UNLOCK_ACCOUNT",
                                    Map.of("timestamp", now)
                            ))
                            .doOnSuccess(v ->
                                    log.info("✅ User {} unlocked successfully", user.getEmail()));
                });
    }

    /* =========================
       Password Management
       ========================= */

    /**
     * Initiate forced password reset for a user
     *
     * @param userId User requiring password reset
     * @param ipAddress Optional IP address to invalidate specific session
     */
    public Mono<Void> initiateForcedPasswordReset(String userId, @Nullable String ipAddress) {
        Instant now = clock.instant();

        log.info("🔑 Initiating forced password reset for user {} at {}", userId, now);

        return userRepository.findById(userId)
                .flatMap(user -> {
                    // Set force password change flag
                    user.setForcePasswordChange(true);
                    user.setUpdatedAt(now);

                    return userRepository.update(user)
                            .then(invalidateSessionsForPasswordReset(userId, ipAddress))
                            .then(logPasswordResetEvent(userId, now))
                            .doOnSuccess(v ->
                                    log.info("✅ Forced password reset initiated for {}",
                                            user.getEmail()))
                            .doOnError(e ->
                                    log.error("❌ Failed to initiate password reset for {}: {}",
                                            user.getEmail(), e.getMessage()));
                });
    }

    /**
     * Invalidate sessions for password reset
     */
    private Mono<Void> invalidateSessionsForPasswordReset(String userId, @Nullable String ipAddress) {
        if (ipAddress != null) {
            log.debug("Invalidating session for user {} from IP {}", userId, ipAddress);
            return sessionService.invalidateSession(userId, ipAddress);
        } else {
            log.debug("Invalidating all sessions for user {}", userId);
            return sessionService.invalidateAllSessionsForUser(userId);
        }
    }

    /**
     * Log password reset event
     */
    private Mono<Void> logPasswordResetEvent(String userId, Instant now) {
        AuditEventLog event = AuditEventLog.forUserAction(
                "FORCED_PASSWORD_RESET",
                userId,
                "SYSTEM",
                Map.of(
                        "trigger", "admin_action",
                        "timestamp", now
                )
        );

        return auditLogService.logEventLog(event);
    }

    /* =========================
       User Queries
       ========================= */

    /**
     * Find users with advanced filtering
     *
     * @param role Filter by role
     * @param status Filter by status
     * @param email Filter by email
     * @param createdAfter Filter by creation date (after)
     * @param createdBefore Filter by creation date (before)
     * @return Flux of matching users
     */
    public Flux<User> findUsersWithFilters(
            Optional<String> role,
            Optional<String> status,
            Optional<String> email,
            Optional<Instant> createdAfter,
            Optional<Instant> createdBefore
    ) {
        log.debug("🔍 Searching users with filters - role: {}, status: {}, email: {}",
                role, status, email);

        CollectionReference usersRef = firestore.collection(COLLECTION_USERS);
        Query query = usersRef;

        // Apply filters
        if (role.isPresent()) {
            query = query.whereEqualTo("role", role.get());
        }
        if (status.isPresent()) {
            query = query.whereEqualTo("status", status.get());
        }
        if (email.isPresent()) {
            query = query.whereEqualTo("email", email.get());
        }
        if (createdAfter.isPresent()) {
            query = query.whereGreaterThanOrEqualTo("createdAt", createdAfter.get());
        }
        if (createdBefore.isPresent()) {
            query = query.whereLessThanOrEqualTo("createdAt", createdBefore.get());
        }

        ApiFuture<QuerySnapshot> queryFuture = query.get();

        return FirestoreUtils.apiFutureToMono(queryFuture)
                .flatMapMany(snapshot -> Flux.fromIterable(snapshot.getDocuments()))
                .map(doc -> doc.toObject(User.class))
                .doOnComplete(() -> log.debug("✅ User search completed"))
                .doOnError(e -> log.error("❌ User search failed: {}", e.getMessage()));
    }

    /**
     * Get all users by status
     *
     * @param status User status to filter by
     * @return Flux of users with matching status
     */
    public Flux<User> findUsersByStatus(UserStatus status) {
        log.debug("🔍 Finding users with status: {}", status);

        return userRepository.findByStatus(status)
                .doOnComplete(() -> log.debug("✅ Status search completed for: {}", status));
    }

    /**
     * Count users by status
     *
     * @param status User status
     * @return Count of users
     */
    public Mono<Long> countUsersByStatus(UserStatus status) {
        log.debug("🔢 Counting users with status: {}", status);

        return userRepository.findByStatus(status)
                .count()
                .doOnSuccess(count -> log.debug("✅ Found {} users with status {}", count, status));
    }

    /* =========================
       Login History & Session Management
       ========================= */

    /**
     * Get login history for a user with optional filters
     *
     * @param userId User ID
     * @param ipAddress Optional IP address filter
     * @param device Optional device filter
     * @param after Optional start date filter
     * @param before Optional end date filter
     * @return Flux of session records
     */
    public Flux<SessionRecord> getLoginHistory(
            String userId,
            Optional<String> ipAddress,
            Optional<String> device,
            Optional<Instant> after,
            Optional<Instant> before
    ) {
        log.debug("📜 Fetching login history for user {} with filters", userId);

        CollectionReference sessionsRef = firestore.collection("sessions");
        Query query = sessionsRef.whereEqualTo("userId", userId);

        // Apply filters
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
                .map(doc -> doc.toObject(SessionRecord.class))
                .doOnComplete(() -> log.debug("✅ Login history fetch completed for user {}", userId))
                .doOnError(e -> log.error("❌ Failed to fetch login history: {}", e.getMessage()));
    }

    /**
     * Get recent login activity for a user
     *
     * @param userId User ID
     * @param limit Number of recent sessions to retrieve
     * @return Flux of recent sessions
     */
    public Flux<SessionRecord> getRecentLoginActivity(String userId, int limit) {
        log.debug("📊 Fetching {} recent logins for user {}", limit, userId);

        CollectionReference sessionsRef = firestore.collection("sessions");
        Query query = sessionsRef
                .whereEqualTo("userId", userId)
                .orderBy("loginTime", Query.Direction.DESCENDING)
                .limit(limit);

        return FirestoreUtils.apiFutureToMono(query.get())
                .flatMapMany(snapshot -> Flux.fromIterable(snapshot.getDocuments()))
                .map(doc -> doc.toObject(SessionRecord.class))
                .doOnComplete(() -> log.debug("✅ Recent activity fetch completed"));
    }

    /**
     * Invalidate all active sessions for a user
     *
     * @param userId User ID
     * @param performedById Admin performing the action
     */
    public Mono<Void> invalidateAllUserSessions(String userId, String performedById) {
        Instant now = clock.instant();

        log.info("🚪 Invalidating all sessions for user {} by {}", userId, performedById);

        return sessionService.invalidateAllSessionsForUser(userId)
                .then(logStatusChange(
                        userId,
                        performedById,
                        "INVALIDATE_ALL_SESSIONS",
                        Map.of("timestamp", now)
                ))
                .doOnSuccess(v ->
                        log.info("✅ All sessions invalidated for user {}", userId));
    }

    /* =========================
       Statistics & Reporting
       ========================= */

    /**
     * Get user statistics summary
     */
    public Mono<Map<String, Long>> getUserStatistics() {
        log.debug("📊 Generating user statistics");

        return Mono.zip(
                        countUsersByStatus(UserStatus.ACTIVE),
                        countUsersByStatus(UserStatus.PENDING_APPROVAL),
                        countUsersByStatus(UserStatus.SUSPENDED),
                        countUsersByStatus(UserStatus.REJECTED)
                ).map(tuple -> Map.of(
                        "active", tuple.getT1(),
                        "pending", tuple.getT2(),
                        "suspended", tuple.getT3(),
                        "rejected", tuple.getT4(),
                        "total", tuple.getT1() + tuple.getT2() + tuple.getT3() + tuple.getT4()
                ))
                .doOnSuccess(stats ->
                        log.info("✅ User statistics - Active: {}, Pending: {}, Suspended: {}, Total: {}",
                                stats.get("active"), stats.get("pending"),
                                stats.get("suspended"), stats.get("total")));
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Log status change audit event
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
                    log.debug("📝 {} logged for user {} by {}", actionType, userId, performedById);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Mask sensitive data for logging
     */
    public String maskSensitive(String value, String type) {
        if (value == null) return null;

        return switch (type) {
            case "email" -> value.replaceAll("(?<=.).(?=[^@]*?.@)", "*");
            case "ip" -> value.replaceAll("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b",
                    "$1.***.***.$4");
            case "device" -> value.length() > 4 ?
                    value.substring(0, 2) + "***" + value.substring(value.length() - 2) : "***";
            case "phone" -> value.length() > 4 ?
                    "***" + value.substring(value.length() - 4) : "***";
            default -> "***";
        };
    }
}