package com.techStack.authSys.service.session;

import com.google.api.client.util.Value;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteBatch;
import com.google.cloud.firestore.WriteResult;
import com.google.firebase.auth.FirebaseAuth;
import com.techStack.authSys.exception.security.SessionException;
import com.techStack.authSys.models.session.SessionStatus;
import com.techStack.authSys.repository.sucurity.RateLimiterService;
import com.techStack.authSys.repository.session.SessionExpirationService;
import com.techStack.authSys.service.notification.EmailService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Service
@Slf4j
public class SessionExpirationServiceImpl implements SessionExpirationService {

    private static final String SESSION_COLLECTION = "sessions";

    private final Firestore firestore;
    private final FirebaseAuth firebaseAuth;
    private final AuditLogService auditLogService;
    private final EmailService emailService;
    private final RateLimiterService.SessionService sessionService;

    @Value("${security.session.inactivity-timeout-minutes:30}")
    private int inactivityTimeoutMinutes;

    @Value("${security.session.max-duration-hours:24}")
    private int maxSessionDurationHours;

    public SessionExpirationServiceImpl(Firestore firestore,
                                        FirebaseAuth firebaseAuth,
                                        AuditLogService auditLogService,
                                        EmailService emailService,
                                        @Lazy RateLimiterService.SessionService sessionService) {
        this.firestore = firestore;
        this.firebaseAuth = firebaseAuth;
        this.auditLogService = auditLogService;
        this.emailService = emailService;
        this.sessionService = sessionService;
    }

    @Override
    public Mono<Void> forceLogout(String userId) {
        return Mono.defer(() -> {
            log.info("Initiating forced logout for user {}", userId);

            return Mono.fromCallable(() -> firebaseAuth.getUser(userId))
                    .subscribeOn(Schedulers.boundedElastic())
                    .flatMap(userRecord -> {
                        // Step 1: Revoke Firebase tokens
                        return revokeFirebaseTokens(userId)
                                // Step 2: Invalidate all sessions
                                .then(invalidateAllSessions(userId))
                                // Step 3: Notify user
                                .then(notifyUserOfForcedLogout(userRecord.getEmail()))
                                // Step 4: Log the event
                                .then(logForcedLogoutEvent(userId));
                    })
                    .onErrorResume(e -> {
                        log.error("Failed to force logout for user {}: {}", userId, e.getMessage());
                        auditLogService.logSystemEvent(
                                "FORCED_LOGOUT_FAILURE",
                                "Failed to force logout for user " + userId + ": " + e.getMessage()
                        );
                        return Mono.error(new SessionException("Failed to force logout"));
                    });
        });
    }

    @Scheduled(cron = "${security.session.cleanup-cron:0 */5 * * * *}")
    public void cleanupExpiredSessions() {
        log.info("Starting session cleanup job");

        try {
            // Cleanup inactive sessions
            cleanupInactiveSessions()
                    // Cleanup expired sessions
                    .then(cleanupDurationExpiredSessions())
                    .subscribe(
                            null,
                            e -> log.error("Session cleanup failed: {}", e.getMessage()),
                            () -> log.info("Session cleanup completed successfully")
                    );
        } catch (Exception e) {
            log.error("Critical error in session cleanup job: {}", e.getMessage());
            auditLogService.logSystemEvent(
                    "SESSION_CLEANUP_FAILURE",
                    "Session cleanup job failed: " + e.getMessage()
            );
        }
    }

    private Mono<Void> cleanupInactiveSessions() {
        // Calculate the cutoff time for inactive sessions
        Instant cutoffInstant = Instant.now().minus(inactivityTimeoutMinutes, ChronoUnit.MINUTES);
        Timestamp cutoffTimestamp = Timestamp.ofTimeSecondsAndNanos(cutoffInstant.getEpochSecond(), cutoffInstant.getNano());

        return Mono.fromFuture(
                FirestoreUtil.toCompletableFuture(
                        firestore.collection("sessions")
                                .whereEqualTo("status", SessionStatus.ACTIVE)
                                .whereLessThan("createdAt", cutoffTimestamp) // ✅ FIXED: Use `whereLessThan`
                                .get()
                )
        ).flatMap(querySnapshot -> {
            if (querySnapshot.isEmpty()) {
                log.debug("No inactive sessions found");
                return Mono.empty();
            }

            log.info("Found {} inactive sessions to cleanup", querySnapshot.size());
            WriteBatch batch = firestore.batch();

            querySnapshot.getDocuments().forEach(doc -> {
                batch.update(doc.getReference(),
                        "status", SessionStatus.EXPIRED,
                        "endedAt", Timestamp.now()); // ✅ Firestore uses `Timestamp.now()`
            });

            // Convert `ApiFuture<List<WriteResult>>` to `CompletableFuture`
            CompletableFuture<List<WriteResult>> futureBatchCommit = FirestoreUtil.toCompletableFuture(batch.commit());

            return Mono.fromFuture(futureBatchCommit)
                    .doOnSuccess(v -> log.info("Successfully cleaned up {} inactive sessions", querySnapshot.size()))
                    .then();
        });
    }

    private Mono<Void> cleanupDurationExpiredSessions() {
        Instant cutoff = Instant.now().minus(maxSessionDurationHours, ChronoUnit.HOURS);

        return Mono.fromFuture(

        FirestoreUtil.toCompletableFuture( // Convert ApiFuture<QuerySnapshot> properly
                        firestore.collection("sessions")
                                .whereEqualTo("status", SessionStatus.ACTIVE)
                                .whereLessThan("createdAt", cutoff)
                                .get()
                )
                ).flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        log.debug("No duration-expired sessions found");
                        return Mono.empty();
                    }

                    log.info("Found {} duration-expired sessions to cleanup", querySnapshot.size());
                    WriteBatch batch = firestore.batch();

                    querySnapshot.getDocuments().forEach(doc -> {
                        batch.update(doc.getReference(),
                                "status", SessionStatus.EXPIRED,
                                "endedAt", Instant.now());
                    });
            // Convert `ApiFuture<List<WriteResult>>` to `CompletableFuture`
            CompletableFuture<List<WriteResult>> futureBatchCommit = FirestoreUtil.toCompletableFuture(batch.commit());
                    return Mono.fromFuture(futureBatchCommit)
                            .doOnSuccess(v ->
                                    log.info("Successfully cleaned up {} duration-expired sessions", querySnapshot.size())
                            )
                            .then();
                });
    }

    private Mono<Void> revokeFirebaseTokens(String userId) {
        return Mono.fromCallable(() -> {
                    firebaseAuth.revokeRefreshTokens(userId);
                    log.debug("Revoked Firebase tokens for user {}", userId);
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic()).then();
    }

    private Mono<Void> invalidateAllSessions(String userId) {
        return sessionService.invalidateAllSessionsForUser(userId)
                .doOnSuccess(v -> log.debug("Invalidated all sessions for user {}", userId));
    }

    private Mono<Void> notifyUserOfForcedLogout(String email) {
        return Mono.fromCallable(() -> {
                    String subject = "Security Notice: Your Sessions Were Terminated";
                    String message = "For security reasons, all your active sessions have been terminated.";
                    emailService.sendSecurityNotification(email, subject, message);
                    log.debug("Sent forced logout notification to {}", email);
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.warn("Failed to send forced logout notification: {}", e.getMessage());
                    return Mono.empty(); // Don't fail the whole operation for notification
                }).then();
    }

    private Mono<Void> logForcedLogoutEvent(String userId) {
        return Mono.fromRunnable(() ->
                        auditLogService.logUserEvent(
                                userId,
                                "FORCED_LOGOUT",
                                "All sessions terminated by system"
                        )
                )
                .subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> checkAndExpireSessions(String userId) {
        return Mono.defer(() -> {
            Instant now = Instant.now();
            Instant activityCutoff = now.minus(inactivityTimeoutMinutes, ChronoUnit.MINUTES);
            Instant durationCutoff = now.minus(maxSessionDurationHours, ChronoUnit.HOURS);

            return Mono.fromFuture(
                            FirestoreUtil.toCompletableFuture( // Convert ApiFuture<QuerySnapshot> properly
                                    firestore.collection("sessions")
                                            .whereEqualTo("userId", userId)
                                            .whereLessThan("status", SessionStatus.ACTIVE)
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

                            Instant lastActivity = (lastActivityTimestamp != null) ? lastActivityTimestamp.toDate().toInstant() : Instant.MIN;
                            Instant createdAt = (createdAtTimestamp != null) ? createdAtTimestamp.toDate().toInstant() : Instant.MIN;

                            return lastActivity.isBefore(activityCutoff) || createdAt.isBefore(durationCutoff);
                        });

                        if (needsExpiration) {
                            return forceLogout(userId);
                        }
                        return Mono.empty();
                    });
        });
    }
    /**
     * Checks if a session is valid
     */
    @Override
    public Mono<Boolean> isSessionValid(String sessionId) {
        return Mono.defer(() ->
                Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .document(sessionId)
                                        .get()
                        )
                ).flatMap(sessionDoc -> {
                    if (!sessionDoc.exists()) {
                        log.warn("Session {} not found", sessionId);
                        return Mono.just(false);
                    }

                    Timestamp expiresAt = sessionDoc.get("expiresAt", Timestamp.class);
                    if (expiresAt == null || expiresAt.toDate().before(new java.util.Date())) {
                        log.info("Session {} has expired", sessionId);
                        return Mono.just(false);
                    }

                    return Mono.just(true);
                })
        ).onErrorResume(e -> {
            log.error("Error checking session {}: {}", sessionId, e.getMessage());
            return Mono.just(false);
        }).subscribeOn(Schedulers.boundedElastic());
    }


    /**
     * Deletes a specific session
     */
    @Override
    public Mono<Void> deleteSession(String sessionId) {
        return Mono.defer(() ->
                Mono.fromFuture(
                                FirestoreUtil.toCompletableFuture(
                                        firestore.collection(SESSION_COLLECTION)
                                                .document(sessionId)
                                                .delete()
                                )
                        ).doOnSuccess(v -> log.info("Deleted session: {}", sessionId))
                        .doOnError(e -> {
                            log.error("Error deleting session {}: {}", sessionId, e.getMessage());
                            auditLogService.logSystemEvent(
                                    "SESSION_DELETION_FAILURE",
                                    "Failed to delete session " + sessionId
                            );
                            throw new SessionException("Failed to delete session");
                        }).then() // Ensures the return type is `Mono<Void>`
        ).subscribeOn(Schedulers.boundedElastic());
    }


    /**
     * Periodic cleanup for expired sessions
     */
    @Scheduled(cron = "${security.session.cleanup-cron:0 0 * * * *}")
    @Override
    public Mono<Void> removeExpiredSessions() {
        return Mono.defer(() ->
                Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .whereLessThan("expiresAt", Timestamp.now())
                                        .get()
                        )
                ).flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        log.debug("No expired sessions found");
                        return Mono.empty();
                    }

                    WriteBatch batch = firestore.batch();
                    querySnapshot.getDocuments().forEach(doc -> batch.delete(doc.getReference()));

                    return Mono.fromFuture(
                            FirestoreUtil.toCompletableFuture(batch.commit())
                    ).doOnSuccess(v -> {
                        log.info("Deleted {} expired sessions", querySnapshot.size());
                        auditLogService.logSystemEvent(
                                "EXPIRED_SESSIONS_CLEANED",
                                "Cleaned up " + querySnapshot.size() + " expired sessions"
                        );
                    });
                }).onErrorResume(e -> {
                    log.error("Error cleaning up expired sessions: {}", e.getMessage());
                    auditLogService.logSystemEvent(
                            "SESSION_CLEANUP_FAILURE",
                            "Failed to clean up expired sessions: " + e.getMessage()
                    );
                    return Mono.empty();
                })
        ).subscribeOn(Schedulers.boundedElastic()).then();
    }
}
