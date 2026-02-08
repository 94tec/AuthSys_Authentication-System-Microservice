package com.techStack.authSys.service.session;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.cloud.firestore.WriteBatch;
import com.techStack.authSys.dto.internal.SessionRecord;
import com.techStack.authSys.models.audit.AuditEventLog;
import com.techStack.authSys.models.session.Session;
import com.techStack.authSys.models.session.SessionStatus;
import com.techStack.authSys.repository.session.SessionExpirationService;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import com.techStack.authSys.util.firebase.FirestoreUtils;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Session Service Implementation
 *
 * Manages user sessions with Redis caching and Firestore persistence.
 * Uses Clock for all timestamp operations and comprehensive logging.
 */
@Service
@Slf4j
public class SessionServiceImpl implements SessionService {

    /* =========================
       Constants
       ========================= */

    private static final Duration ACTIVE_SESSION_TTL = Duration.ofMinutes(15);
    private static final String SESSION_COLLECTION = "sessions";
    private static final int BATCH_SIZE = 500;

    /* =========================
       Dependencies
       ========================= */

    private final ReactiveRedisTemplate<String, SessionRecord> redisTemplate;
    private final ReactiveRedisTemplate<String, SessionRecord> sessionRecordRedisTemplate;
    private final Firestore firestore;
    private final SessionExpirationService sessionExpirationService;
    private final AuditLogService auditLogService;
    private final Clock clock;

    @Autowired
    public SessionServiceImpl(
            ReactiveRedisTemplate<String, SessionRecord> redisTemplate,
            ReactiveRedisTemplate<String, SessionRecord> sessionRecordRedisTemplate,
            Firestore firestore,
            SessionExpirationService sessionExpirationService,
            AuditLogService auditLogService,
            Clock clock) {
        this.redisTemplate = redisTemplate;
        this.sessionRecordRedisTemplate = sessionRecordRedisTemplate;
        this.firestore = firestore;
        this.sessionExpirationService = sessionExpirationService;
        this.auditLogService = auditLogService;
        this.clock = clock;
    }

    /* =========================
       Session Creation
       ========================= */

    /**
     * Create new session with token expiry times
     */
    @Override
    public Mono<Void> createSession(
            String userId,
            String sessionId,
            String ipAddress,
            String deviceFingerprint,
            String accessToken,
            String refreshToken,
            Instant lastActivity,
            Timestamp firestoreExpiresAt,
            Instant accessTokenExpiry,
            Instant refreshTokenExpiry) {

        Instant creationStart = clock.instant();

        log.info("Creating session at {} for user: {} | Session ID: {} | IP: {}",
                creationStart,
                userId,
                maskSessionId(sessionId),
                HelperUtils.maskIpAddress(ipAddress));

        return buildSession(
                sessionId, userId, ipAddress, deviceFingerprint,
                accessToken, refreshToken, lastActivity, firestoreExpiresAt,
                accessTokenExpiry, refreshTokenExpiry, creationStart
        )
                .flatMap(session -> saveSessionToFirestore(session, creationStart))
                .flatMap(v -> invalidateSessionCache(userId))
                .doOnSuccess(v -> {
                    Instant creationEnd = clock.instant();
                    Duration duration = Duration.between(creationStart, creationEnd);

                    log.info("✅ Session created at {} in {} for user: {} | Session ID: {}",
                            creationEnd,
                            duration,
                            userId,
                            maskSessionId(sessionId));

                    auditLogService.logUserEvent(
                            userId,
                            "SESSION_CREATED",
                            String.format("Session %s created at %s from IP %s",
                                    maskSessionId(sessionId),
                                    creationEnd,
                                    HelperUtils.maskIpAddress(ipAddress))
                    );
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(creationStart, errorTime);

                    log.error("❌ Session creation failed at {} after {} for user {}: {}",
                            errorTime, duration, userId, e.getMessage(), e);

                    auditLogService.logSystemEvent(
                            "SESSION_CREATION_FAILURE",
                            String.format("Failed to create session for user %s at %s: %s",
                                    userId, errorTime, e.getMessage())
                    );
                })
                .then();
    }

    /**
     * Build session object
     */
    private Mono<Session> buildSession(
            String sessionId,
            String userId,
            String ipAddress,
            String deviceFingerprint,
            String accessToken,
            String refreshToken,
            Instant lastActivity,
            Timestamp firestoreExpiresAt,
            Instant accessTokenExpiry,
            Instant refreshTokenExpiry,
            Instant createdAt) {

        return Mono.just(Session.builder()
                .id(sessionId)
                .userId(userId)
                .ipAddress(ipAddress)
                .deviceFingerprint(deviceFingerprint)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .createdAt(createdAt)
                .accessTokenExpiry(accessTokenExpiry)
                .refreshTokenExpiry(refreshTokenExpiry)
                .status(SessionStatus.ACTIVE)
                .lastActivity(lastActivity != null ? lastActivity : createdAt)
                .firestoreExpiresAt(firestoreExpiresAt)
                .build()
        );
    }

    /**
     * Save session to Firestore
     */
    private Mono<Void> saveSessionToFirestore(Session session, Instant startTime) {
        Instant saveStart = clock.instant();

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .document(session.getId())
                                        .set(session)
                        )
                )
                .doOnSuccess(v -> {
                    Instant saveEnd = clock.instant();
                    Duration duration = Duration.between(saveStart, saveEnd);

                    log.debug("Session saved to Firestore at {} in {} - ID: {}",
                            saveEnd, duration, maskSessionId(session.getId()));
                })
                .then();
    }

    /* =========================
       Session Invalidation
       ========================= */

    /**
     * Invalidate session by user ID and IP address
     */
    @Override
    public Mono<Void> invalidateSession(Object userId, String ipAddress) {
        Instant invalidationStart = clock.instant();

        log.info("Invalidating sessions at {} for user: {} from IP: {}",
                invalidationStart, userId, HelperUtils.maskIpAddress(ipAddress));

        return invalidateSessionsInFirestore(userId, ipAddress, invalidationStart)
                .flatMap(count -> invalidateSessionCache(userId.toString())
                        .thenReturn(count))
                .doOnSuccess(count -> {
                    Instant invalidationEnd = clock.instant();
                    Duration duration = Duration.between(invalidationStart, invalidationEnd);

                    log.info("✅ Invalidated {} session(s) at {} in {} for user: {}",
                            count, invalidationEnd, duration, userId);
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Session invalidation failed at {} for user {}: {}",
                            errorTime, userId, e.getMessage(), e);
                })
                .then();
    }

    /**
     * Invalidate all sessions for user
     */
    @Override
    public Mono<Void> invalidateAllSessionsForUser(Object userId) {
        Instant invalidationStart = clock.instant();

        log.warn("🔒 Invalidating ALL sessions at {} for user: {}", invalidationStart, userId);

        return invalidateAllSessionsInFirestore(userId, invalidationStart)
                .flatMap(count -> invalidateSessionCache(userId.toString())
                        .thenReturn(count))
                .doOnSuccess(count -> {
                    Instant invalidationEnd = clock.instant();
                    Duration duration = Duration.between(invalidationStart, invalidationEnd);

                    log.info("✅ Invalidated ALL {} session(s) at {} in {} for user: {}",
                            count, invalidationEnd, duration, userId);

                    auditLogService.logUserEvent(
                            userId.toString(),
                            "ALL_SESSIONS_INVALIDATED",
                            String.format("All sessions invalidated at %s - Count: %d",
                                    invalidationEnd, count)
                    );
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to invalidate all sessions at {} for user {}: {}",
                            errorTime, userId, e.getMessage(), e);
                })
                .then();
    }

    /**
     * Invalidate user sessions in Redis cache
     */
    @Override
    public Mono<Void> invalidateUserSessions(String userId) {
        return invalidateSessionCache(userId);
    }

    /**
     * Invalidate session cache
     */
    private Mono<Void> invalidateSessionCache(String userId) {
        Instant cacheInvalidationStart = clock.instant();
        String pattern = "session:user:" + userId + ":*";
        String activeSessionsKey = "active_sessions:" + userId;

        return redisTemplate.keys(pattern)
                .flatMap(redisTemplate::delete)
                .then(sessionRecordRedisTemplate.delete(activeSessionsKey))
                .doOnSuccess(v -> {
                    Instant cacheInvalidationEnd = clock.instant();
                    Duration duration = Duration.between(cacheInvalidationStart, cacheInvalidationEnd);

                    log.debug("Cache invalidated at {} in {} for user: {}",
                            cacheInvalidationEnd, duration, userId);
                })
                .then();
    }

    /**
     * Invalidate sessions in Firestore (by user and IP)
     */
    private Mono<Integer> invalidateSessionsInFirestore(
            Object userId,
            String ipAddress,
            Instant invalidationTime) {

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .whereEqualTo("userId", userId)
                                        .whereEqualTo("ipAddress", ipAddress)
                                        .whereEqualTo("status", SessionStatus.ACTIVE.name())
                                        .get()
                        )
                )
                .flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        log.debug("No active sessions found for user {} with IP {} at {}",
                                userId, HelperUtils.maskIpAddress(ipAddress), invalidationTime);
                        return Mono.just(0);
                    }

                    return batchUpdateSessionStatus(
                            querySnapshot.getDocuments(),
                            SessionStatus.INVALIDATED,
                            invalidationTime
                    );
                });
    }

    /**
     * Invalidate all sessions in Firestore (by user only)
     */
    private Mono<Integer> invalidateAllSessionsInFirestore(
            Object userId,
            Instant invalidationTime) {

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .whereEqualTo("userId", userId)
                                        .whereEqualTo("status", SessionStatus.ACTIVE.name())
                                        .get()
                        )
                )
                .flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        log.debug("No active sessions found for user {} at {}",
                                userId, invalidationTime);
                        return Mono.just(0);
                    }

                    return batchUpdateSessionStatus(
                            querySnapshot.getDocuments(),
                            SessionStatus.INVALIDATED,
                            invalidationTime
                    );
                });
    }

    /**
     * Batch update session status
     */
    private Mono<Integer> batchUpdateSessionStatus(
            List<QueryDocumentSnapshot> documents,
            SessionStatus newStatus,
            Instant endTime) {

        List<WriteBatch> batches = new ArrayList<>();
        WriteBatch batch = firestore.batch();

        int count = 0;
        for (DocumentSnapshot document : documents) {
            batch.update(document.getReference(),
                    "status", newStatus.name(),
                    "endedAt", endTime);
            count++;

            if (count % BATCH_SIZE == 0) {
                batches.add(batch);
                batch = firestore.batch();
            }
        }

        if (count % BATCH_SIZE != 0) {
            batches.add(batch);
        }

        final int totalCount = count;

        return Flux.fromIterable(batches)
                .flatMap(b -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(b.commit())))
                .then(Mono.just(totalCount));
    }

    /* =========================
       Session Validation
       ========================= */

    /**
     * Validate session
     */
    @Override
    public Mono<Boolean> validateSession(String userId, String accessToken) {
        Instant validationStart = clock.instant();
        Timestamp currentTimestamp = Timestamp.ofTimeSecondsAndNanos(
                validationStart.getEpochSecond(), validationStart.getNano()
        );

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .whereEqualTo("userId", userId)
                                        .whereEqualTo("accessToken", accessToken)
                                        .whereEqualTo("status", SessionStatus.ACTIVE.name())
                                        .whereGreaterThan("accessTokenExpiry", currentTimestamp)
                                        .limit(1)
                                        .get()
                        )
                )
                .flatMap(querySnapshot -> {
                    boolean isValid = !querySnapshot.isEmpty();

                    Instant validationEnd = clock.instant();
                    Duration duration = Duration.between(validationStart, validationEnd);

                    if (!isValid) {
                        log.warn("❌ Invalid session at {} for user: {} - forcing logout",
                                validationEnd, userId);

                        return sessionExpirationService.forceLogout(userId)
                                .thenReturn(false);
                    }

                    log.debug("✅ Session validated at {} in {} for user: {}",
                            validationEnd, duration, userId);

                    return Mono.just(true);
                });
    }

    /* =========================
       Active Sessions
       ========================= */

    /**
     * Get active sessions with Redis caching
     */
    @Override
    public Flux<SessionRecord> getActiveSessionsCached(String userId) {
        Instant cacheCheckStart = clock.instant();
        String redisKey = "active_sessions:" + userId;

        return sessionRecordRedisTemplate.opsForList()
                .range(redisKey, 0, -1)
                .cast(SessionRecord.class)
                .doOnNext(session -> {
                    Instant cacheHitTime = clock.instant();
                    log.debug("Cache HIT at {} for user: {} | Session: {}",
                            cacheHitTime, userId, maskSessionId(session.getSessionId()));
                })
                .switchIfEmpty(
                        Flux.defer(() -> {
                            Instant cacheMissTime = clock.instant();
                            log.info("Cache MISS at {} for user: {} - fetching from Firestore",
                                    cacheMissTime, userId);

                            return fetchActiveSessionsFromFirestore(userId)
                                    .flatMap(sessions -> {
                                        if (sessions.isEmpty()) {
                                            return Mono.empty();
                                        }

                                        return cacheActiveSessions(redisKey, sessions)
                                                .thenReturn(sessions);
                                    })
                                    .flatMapMany(Flux::fromIterable);
                        })
                )
                .onErrorResume(ex -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Error fetching sessions at {} for user {}: {}",
                            errorTime, userId, ex.getMessage());

                    fallbackAuditLog(userId, ex).subscribe();
                    return Flux.empty();
                });
    }

    /**
     * Fetch active sessions from Firestore
     */
    @Override
    public Mono<List<SessionRecord>> fetchActiveSessionsFromFirestore(String userId) {
        Instant fetchStart = clock.instant();

        return FirestoreUtils.apiFutureToMono(
                        firestore.collection(SESSION_COLLECTION)
                                .whereEqualTo("userId", userId)
                                .whereEqualTo("status", SessionStatus.ACTIVE.name())
                                .get()
                )
                .map(snapshot -> snapshot.getDocuments().stream()
                        .map(doc -> doc.toObject(SessionRecord.class))
                        .toList()
                )
                .doOnSuccess(sessions -> {
                    Instant fetchEnd = clock.instant();
                    Duration duration = Duration.between(fetchStart, fetchEnd);

                    log.debug("Fetched {} active session(s) at {} in {} from Firestore for user: {}",
                            sessions.size(), fetchEnd, duration, userId);
                });
    }

    /**
     * Cache active sessions in Redis
     */
    private Mono<Void> cacheActiveSessions(String redisKey, List<SessionRecord> sessions) {
        Instant cacheStart = clock.instant();

        return sessionRecordRedisTemplate.opsForList()
                .rightPushAll(redisKey, sessions)
                .then(sessionRecordRedisTemplate.expire(redisKey, ACTIVE_SESSION_TTL))
                .doOnSuccess(v -> {
                    Instant cacheEnd = clock.instant();
                    Duration duration = Duration.between(cacheStart, cacheEnd);

                    log.debug("Cached {} session(s) at {} in {} with TTL: {}",
                            sessions.size(), cacheEnd, duration, ACTIVE_SESSION_TTL);
                })
                .then();
    }

    /* =========================
       Session Updates
       ========================= */

    /**
     * Update session tokens
     */
    @Override
    public Mono<Void> updateSessionTokens(
            String userId,
            String newAccessToken,
            String newRefreshToken,
            String ipAddress) {

        Instant updateStart = clock.instant();

        log.debug("Updating session tokens at {} for user: {} from IP: {}",
                updateStart, userId, HelperUtils.maskIpAddress(ipAddress));

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .whereEqualTo("userId", userId)
                                        .whereEqualTo("ipAddress", ipAddress)
                                        .whereEqualTo("status", SessionStatus.ACTIVE.name())
                                        .limit(1)
                                        .get()
                        )
                )
                .flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        Instant errorTime = clock.instant();
                        log.warn("No active session found at {} for user {} with IP {}",
                                errorTime, userId, HelperUtils.maskIpAddress(ipAddress));
                        return Mono.empty();
                    }

                    DocumentSnapshot doc = querySnapshot.getDocuments().get(0);
                    return Mono.fromFuture(
                            FirestoreUtil.toCompletableFuture(
                                    doc.getReference().update(
                                            "accessToken", newAccessToken,
                                            "refreshToken", newRefreshToken,
                                            "lastActivity", updateStart
                                    )
                            )
                    );
                })
                .flatMap(v -> invalidateSessionCache(userId))
                .doOnSuccess(v -> {
                    Instant updateEnd = clock.instant();
                    Duration duration = Duration.between(updateStart, updateEnd);

                    log.info("✅ Session tokens updated at {} in {} for user: {}",
                            updateEnd, duration, userId);
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Token update failed at {} for user {}: {}",
                            errorTime, userId, e.getMessage());
                })
                .then();
    }

    /**
     * Record session activity
     */
    @Override
    public Mono<Void> recordSessionActivity(String sessionId) {
        Instant activityTime = clock.instant();

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .document(sessionId)
                                        .update("lastActivity", activityTime)
                        )
                )
                .doOnSuccess(v -> log.debug("Recorded activity at {} for session: {}",
                        activityTime, maskSessionId(sessionId)))
                .doOnError(e -> log.error("Failed to record activity at {} for session {}: {}",
                        activityTime, maskSessionId(sessionId), e.getMessage()))
                .then();
    }

    /* =========================
       Cleanup Operations
       ========================= */

    /**
     * Cleanup after blacklist removal
     */
    @Override
    public Mono<Void> cleanupAfterBlacklistRemoval(String encryptedIp) {
        Instant cleanupStart = clock.instant();

        log.info("Cleaning up blocked sessions at {} for IP: {}",
                cleanupStart, HelperUtils.maskIpAddress(encryptedIp));

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(SESSION_COLLECTION)
                                        .whereEqualTo("ipAddress", encryptedIp)
                                        .whereEqualTo("status", SessionStatus.BLOCKED.name())
                                        .get()
                        )
                )
                .flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        log.debug("No blocked sessions found at {} for IP: {}",
                                clock.instant(), HelperUtils.maskIpAddress(encryptedIp));
                        return Mono.just(0);
                    }

                    return batchUpdateSessionStatus(
                            querySnapshot.getDocuments(),
                            SessionStatus.INVALIDATED,
                            cleanupStart
                    );
                })
                .doOnSuccess(count -> {
                    Instant cleanupEnd = clock.instant();
                    Duration duration = Duration.between(cleanupStart, cleanupEnd);

                    log.info("✅ Cleaned up {} blocked session(s) at {} in {} for IP: {}",
                            count, cleanupEnd, duration, HelperUtils.maskIpAddress(encryptedIp));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Cleanup failed at {} for IP {}: {}",
                            errorTime, HelperUtils.maskIpAddress(encryptedIp), e.getMessage());
                })
                .then();
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Mask session ID for logging
     */
    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 6) return "***";
        return sessionId.substring(0, 3) + "***" + sessionId.substring(sessionId.length() - 3);
    }

    /**
     * Fallback audit log
     */
    private Mono<Void> fallbackAuditLog(String userId, Throwable ex) {
        Instant errorTime = clock.instant();

        AuditEventLog event = AuditEventLog.forSystemError(
                "ACTIVE_SESSION_CACHE_FAILURE",
                userId,
                Map.of(
                        "error", ex.getMessage(),
                        "timestamp", errorTime.toString(),
                        "timestampMillis", errorTime.toEpochMilli()
                )
        );

        return auditLogService.logEventLog(event)
                .doOnError(err -> log.warn("Failed to log fallback audit event at {} for user {}: {}",
                        clock.instant(), userId, err.getMessage()))
                .onErrorResume(err -> Mono.empty());
    }
}