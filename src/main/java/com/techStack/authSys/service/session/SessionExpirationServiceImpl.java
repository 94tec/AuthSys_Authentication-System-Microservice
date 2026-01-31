package com.techStack.authSys.service.session;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteBatch;
import com.google.cloud.firestore.WriteResult;
import com.google.firebase.auth.FirebaseAuth;
import com.techStack.authSys.exception.security.SessionException;
import com.techStack.authSys.models.session.SessionStatus;
import com.techStack.authSys.repository.session.SessionExpirationService;
import com.techStack.authSys.repository.sucurity.RateLimiterService;
import com.techStack.authSys.service.notification.EmailService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static com.techStack.authSys.constants.SecurityConstants.SESSION_COLLECTION;

/**
 * Session Expiration Service Implementation
 *
 * Manages session lifecycle, expiration, and cleanup.
 * Uses Clock for all timestamp operations.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SessionExpirationServiceImpl implements SessionExpirationService {

    /* =========================
       Dependencies
       ========================= */

    private final Firestore firestore;
    private final FirebaseAuth firebaseAuth;
    private final AuditLogService auditLogService;
    private final EmailService emailService;
    private final Clock clock;

    @Lazy
    private final RateLimiterService.SessionService sessionService;

    /* =========================
       Configuration
       ========================= */

    @Value("${security.session.inactivity-timeout-minutes:30}")
    private int inactivityTimeoutMinutes;

    @Value("${security.session.max-duration-hours:24}")
    private int maxSessionDurationHours;

    /* =========================
       Force Logout
       ========================= */

    @Override
    public Mono<Void> forceLogout(String userId) {
        Instant now = clock.instant();

        return Mono.defer(() -> {
            log.info("Initiating forced logout for user {} at {}", userId, now);

            return Mono.fromCallable(() -> firebaseAuth.getUser(userId))
                    .subscribeOn(Schedulers.boundedElastic())
                    .flatMap(userRecord -> {
                        // Step 1: Revoke Firebase tokens
                        return revokeFirebaseTokens(userId, now)
                                // Step 2: Invalidate all sessions
                                .then(invalidateAllSessions(userId, now))
                                // Step 3: Notify user
                                .then(notifyUserOfForcedLogout(userRecord.getEmail(), now))
                                // Step 4: Log the event
                                .then(logForcedLogoutEvent(userId, now));
                    })
                    .onErrorResume(e -> {
                        log.error("Failed to force logout for user {} at {}: {}",
                                userId, now, e.getMessage());

                        auditLogService.logSystemEvent(
                                "FORCED_LOGOUT_FAILURE",
                                "Failed to force logout for user " + userId + " at " + now + ": " + e.getMessage()
                        );

                        return Mono.error(new SessionException("Failed to force logout"));
                    });
        });
    }

    /* =========================
       Session Cleanup (Scheduled)
       ========================= */

    /**
     * Cleanup expired sessions (runs every 5 minutes)
     */
    @Scheduled(cron = "${security.session.cleanup-cron:0 */5 * * * *}")
    public void cleanupExpiredSessions() {
        Instant now = clock.instant();
        log.info("Starting session cleanup job at {}", now);

        try {
            // Cleanup inactive sessions
            cleanupInactiveSessions(now)
                    // Cleanup expired sessions
                    .then(cleanupDurationExpiredSessions(now))
                    .subscribe(
                            null,
                            e -> log.error("Session cleanup failed at {}: {}", now, e.getMessage()),
                            () -> log.info("Session cleanup completed successfully at {}", now)
                    );
        } catch (Exception e) {
            log.error("Critical error in session cleanup job at {}: {}", now, e.getMessage());

            auditLogService.logSystemEvent(
                    "SESSION_CLEANUP_FAILURE",
                    "Session cleanup job failed at " + now + ": " + e.getMessage()
            );
        }
    }

    /**
     * Cleanup inactive sessions
     */
    private Mono<Void> cleanupInactiveSessions(Instant now) {
        Instant cutoffInstant = now.minus(inactivityTimeoutMinutes, ChronoUnit.MINUTES);
        Timestamp cutoffTimestamp = Timestamp.ofTimeSecondsAndNanos(
                cutoffInstant.getEpochSecond(), cutoffInstant.getNano()
        );

        return Mono.fromFuture(
                FirestoreUtil.toCompletableFuture(
                        firestore.collection("sessions")
                                .whereEqualTo("status", SessionStatus.ACTIVE)
                                .whereLessThan("lastActivity", cutoffTimestamp)
                                .get()
                )
        ).flatMap(querySnapshot -> {
            if (querySnapshot.isEmpty()) {
                log.debug("No inactive sessions found at {}", now);
                return Mono.empty();
            }

            log.info("Found {} inactive sessions to cleanup at {}",
                    querySnapshot.size(), now);

            WriteBatch batch = firestore.batch();

            querySnapshot.getDocuments().forEach(doc -> {
                batch.update(doc.getReference(),
                        "status", SessionStatus.EXPIRED,
                        "endedAt", now);
            });

            CompletableFuture<List<WriteResult>> futureBatchCommit =
                    FirestoreUtil.toCompletableFuture(batch.commit());

            return Mono.fromFuture(futureBatchCommit)
                    .doOnSuccess(v -> log.info(
                            "Successfully cleaned up {} inactive sessions at {}",
                            querySnapshot.size(), now))
                    .then();
        });
    }

    /**
     * Cleanup duration-expired sessions
     */
    private Mono<Void> cleanupDurationExpiredSessions(Instant now) {
        Instant cutoff = now.minus(maxSessionDurationHours, ChronoUnit.HOURS);

        return Mono.fromFuture(
                FirestoreUtil.toCompletableFuture(
                        firestore.collection("sessions")
                                .whereEqualTo("status", SessionStatus.ACTIVE)
                                .whereLessThan("createdAt", cutoff)
                                .get()
                )
        ).flatMap(querySnapshot -> {
            if (querySnapshot.isEmpty()) {
                log.debug("No duration-expired sessions found at {}", now);
                return Mono.empty();
            }

            log.info("Found {} duration-expired sessions to cleanup at {}",
                    querySnapshot.size(), now);

            WriteBatch batch = firestore.batch();

            querySnapshot.getDocuments().forEach(doc -> {
                batch.update(doc.getReference(),
                        "status", SessionStatus.EXPIRED,
                        "endedAt", now);
            });

            CompletableFuture<List<WriteResult>> futureBatchCommit =
                    FirestoreUtil.toCompletableFuture(batch.commit());

            return Mono.fromFuture(futureBatchCommit)
                    .doOnSuccess(v -> log.info(
                            "Successfully cleaned up {} duration-expired sessions at {}",
                            querySnapshot.size(), now))
                    .then();
        });
    }

    /* =========================
       Token Revocation
       ========================= */

    /**
     * Revoke Firebase tokens
     */
    private Mono<Void> revokeFirebaseTokens(String userId, Instant now) {
        return Mono.fromCallable(() -> {
                    firebaseAuth.revokeRefreshTokens(userId);
                    log.debug("Revoked Firebase tokens for user {} at {}", userId, now);
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Invalidate all sessions
     */
    private Mono<Void> invalidateAllSessions(String userId, Instant now) {
        return sessionService.invalidateAllSessionsForUser(userId)
                .doOnSuccess(v -> log.debug("Invalidated all sessions for user {} at {}",
                        userId, now));
    }

    /* =========================
       Notifications
       ========================= */

    /**
     * Notify user of forced logout
     */
    private Mono<Void> notifyUserOfForcedLogout(String email, Instant now) {
        return Mono.fromCallable(() -> {
                    String subject = "Security Notice: Your Sessions Were Terminated";
                    String message = "For security reasons, all your active sessions have been terminated at " + now;

                    emailService.sendSecurityNotification(email, subject, message);
                    log.debug("Sent forced logout notification to {} at {}", email, now);
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.warn("Failed to send forced logout notification at {}: {}",
                            now, e.getMessage());
                    return Mono.empty(); // Don't fail the whole operation
                })
                .then();
    }

    /* =========================
       Audit Logging
       ========================= */

    /**
     * Log forced logout event
     */
    private Mono<Void> logForcedLogoutEvent(String userId, Instant now) {
        return Mono.fromRunnable(() ->
                        auditLogService.logUserEvent(
                                userId,
                                "FORCED_LOGOUT",
                                "All sessions terminated by system at " + now
                        )
                )
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /* =========================
       Session Validation
       ========================= */

    @Override
    public Mono<Void> checkAndExpireSessions(String userId) {
        Instant now = clock.instant();
        Instant activityCutoff = now.minus(inactivityTimeoutMinutes, ChronoUnit.MINUTES);
        Instant durationCutoff = now.minus(maxSessionDurationHours, ChronoUnit.HOURS);

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection("sessions")
                                        .whereEqualTo("userId", userId)
                                        .whereEqualTo("status", SessionStatus.ACTIVE)
                                        .get()
                        )
                )
                .flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        return Mono.empty();
                    }

                    boolean needsExpiration = querySnapshot.getDocuments().stream().anyMatch(doc -> {
                        Timestamp lastActivityTimestamp = doc.get("lastActivity", Timestamp.class);
                        Timestamp createdAtTimestamp = doc.get("createdAt", Timestamp.class);

                        Instant lastActivity = (lastActivityTimestamp != null) ?
                                lastActivityTimestamp.toDate().toInstant() : Instant.MIN;
                        Instant createdAt = (createdAtTimestamp != null) ?
                                createdAtTimestamp.toDate().toInstant() : Instant.MIN;

                        return lastActivity.isBefore(activityCutoff) ||
                                createdAt.isBefore(durationCutoff);
                    });

                    if (needsExpiration) {
                        return forceLogout(userId);
                    }
                    return Mono.empty();
                });
    }

    /**
     * Check if session is valid
     */
    @Override
    public Mono<Boolean> isSessionValid(String sessionId) {
        Instant now = clock.instant();

        return Mono.defer(() ->
                Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .document(sessionId)
                                        .get()
                        )
                ).flatMap(sessionDoc -> {
                    if (!sessionDoc.exists()) {
                        log.warn("Session {} not found at {}", sessionId, now);
                        return Mono.just(false);
                    }

                    Timestamp expiresAt = sessionDoc.get("expiresAt", Timestamp.class);
                    if (expiresAt == null || expiresAt.toDate().before(java.util.Date.from(now))) {
                        log.info("Session {} has expired at {}", sessionId, now);
                        return Mono.just(false);
                    }

                    return Mono.just(true);
                })
        ).onErrorResume(e -> {
            log.error("Error checking session {} at {}: {}", sessionId, now, e.getMessage());
            return Mono.just(false);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       Session Management
       ========================= */

    /**
     * Delete specific session
     */
    @Override
    public Mono<Void> deleteSession(String sessionId) {
        Instant now = clock.instant();

        return Mono.defer(() ->
                Mono.fromFuture(
                                FirestoreUtil.toCompletableFuture(
                                        firestore.collection(SESSION_COLLECTION)
                                                .document(sessionId)
                                                .delete()
                                )
                        ).doOnSuccess(v -> log.info("Deleted session: {} at {}", sessionId, now))
                        .doOnError(e -> {
                            log.error("Error deleting session {} at {}: {}",
                                    sessionId, now, e.getMessage());

                            auditLogService.logSystemEvent(
                                    "SESSION_DELETION_FAILURE",
                                    "Failed to delete session " + sessionId + " at " + now
                            );

                            throw new SessionException("Failed to delete session");
                        })
                        .then()
        ).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Remove expired sessions (scheduled cleanup)
     */
    @Scheduled(cron = "${security.session.cleanup-cron:0 0 * * * *}")
    @Override
    public Mono<Void> removeExpiredSessions() {
        Instant now = clock.instant();
        Timestamp timestamp = Timestamp.ofTimeSecondsAndNanos(
                now.getEpochSecond(), now.getNano()
        );

        return Mono.defer(() ->
                Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .whereLessThan("expiresAt", timestamp)
                                        .get()
                        )
                ).flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        log.debug("No expired sessions found at {}", now);
                        return Mono.empty();
                    }

                    WriteBatch batch = firestore.batch();
                    querySnapshot.getDocuments().forEach(doc -> batch.delete(doc.getReference()));

                    return Mono.fromFuture(
                            FirestoreUtil.toCompletableFuture(batch.commit())
                    ).doOnSuccess(v -> {
                        log.info("Deleted {} expired sessions at {}",
                                querySnapshot.size(), now);

                        auditLogService.logSystemEvent(
                                "EXPIRED_SESSIONS_CLEANED",
                                "Cleaned up " + querySnapshot.size() + " expired sessions at " + now
                        );
                    });
                }).onErrorResume(e -> {
                    log.error("Error cleaning up expired sessions at {}: {}", now, e.getMessage());

                    auditLogService.logSystemEvent(
                            "SESSION_CLEANUP_FAILURE",
                            "Failed to clean up expired sessions at " + now + ": " + e.getMessage()
                    );

                    return Mono.empty();
                })
        ).subscribeOn(Schedulers.boundedElastic()).then();
    }
}