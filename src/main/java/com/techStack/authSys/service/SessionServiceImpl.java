package com.techStack.authSys.service;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteBatch;
import com.techStack.authSys.dto.SessionRecord;
import com.techStack.authSys.exception.SessionException;
import com.techStack.authSys.models.AuditEventLog;
import com.techStack.authSys.models.Session;
import com.techStack.authSys.models.SessionStatus;
import com.techStack.authSys.repository.RateLimiterService;
import com.techStack.authSys.repository.SessionExpirationService;
import com.techStack.authSys.util.FirestoreUtil;
import com.techStack.authSys.util.FirestoreUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class SessionServiceImpl implements RateLimiterService.SessionService {

    private static final Duration ACTIVE_SESSION_TTL = Duration.ofMinutes(15);
    private static final String SESSION_COLLECTION = "sessions";

    private final ReactiveRedisTemplate<String, SessionRecord> redisTemplate;
    private final ReactiveRedisTemplate<String, SessionRecord> sessionRecordRedisTemplate;

    private final Firestore firestore;
    private final JwtService jwtService;
    private final SessionExpirationService sessionExpirationService;

    private final AuditLogService auditLogService;

    @Autowired
    public SessionServiceImpl(ReactiveRedisTemplate<String, SessionRecord> redisTemplate,
                              ReactiveRedisTemplate<String, SessionRecord> sessionRecordRedisTemplate,
                              Firestore firestore,
                              JwtService jwtService,
                              SessionExpirationService sessionExpirationService,
                              AuditLogService auditLogService) {
        this.redisTemplate = redisTemplate;
        this.sessionRecordRedisTemplate = sessionRecordRedisTemplate;
        this.firestore = firestore;
        this.jwtService = jwtService;
        this.sessionExpirationService = sessionExpirationService;
        this.auditLogService = auditLogService;
    }

    @Override
    public Mono<Void> createSession(String userId, String sessionId, String ipAddress,
                                    String deviceFingerprint, String accessToken,
                                    String refreshToken, Instant lastActivity,
                                    Timestamp firestoreExpiresAt) {

        return buildSession(sessionId, userId, ipAddress, deviceFingerprint,
                accessToken, refreshToken, lastActivity, firestoreExpiresAt)
                .flatMap(session -> Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection("sessions")
                                        .document(sessionId)
                                        .set(session)
                        )
                ))
                .doOnSuccess(v -> {
                    log.info("Session created for user: {} (Session ID: {})", userId, sessionId);
                    auditLogService.logUserEvent(
                            userId,
                            "SESSION_CREATED",
                            "New session created with duration minutes"
                    );
                })
                .doOnError(e -> {
                    log.error("Error creating session for {}: {}", userId, e.getMessage());
                    auditLogService.logSystemEvent(
                            "SESSION_CREATION_FAILURE",
                            "Failed to create session for user " + userId
                    );
                })
                .then();
    }

    public Mono<Session> buildSession(String sessionId, String userId, String ipAddress,
                                      String deviceFingerprint, String accessToken,
                                      String refreshToken, Instant lastActivity,
                                      Timestamp firestoreExpiresAt) {
        return Mono.zip(
                        jwtService.getAccessTokenExpiry(accessToken),
                        jwtService.getRefreshTokenExpiry(refreshToken)
                )
                .map(tuple -> Session.builder()
                        .id(sessionId)
                        .userId(userId)
                        .ipAddress(ipAddress)
                        .deviceFingerprint(deviceFingerprint)
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .createdAt(Instant.now())
                        .accessTokenExpiry(tuple.getT1())  // Access token expiry from Mono
                        .refreshTokenExpiry(tuple.getT2()) // Refresh token expiry from Mono
                        .status(SessionStatus.ACTIVE)
                        .lastActivity(lastActivity)
                        .firestoreExpiresAt(firestoreExpiresAt)
                        .build()
                );
    }

    @Override
    public Mono<Void> invalidateSession(Object userId, String ipAddress) {
        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection("sessions")
                                        .whereEqualTo("userId", userId)
                                        .whereEqualTo("ipAddress", ipAddress)
                                        .whereEqualTo("status", SessionStatus.ACTIVE)
                                        .get()
                        )
                )
                .flatMap(querySnapshot -> {
                    List<WriteBatch> batches = new ArrayList<>();
                    WriteBatch batch = firestore.batch();

                    int count = 0;
                    for (DocumentSnapshot document : querySnapshot.getDocuments()) {
                        batch.update(document.getReference(), "status", SessionStatus.INVALIDATED);
                        count++;

                        if (count % 500 == 0) {
                            batches.add(batch);
                            batch = firestore.batch();
                        }
                    }

                    if (count > 0) {
                        batches.add(batch);
                    }

                    return Flux.fromIterable(batches)
                            .flatMap(b -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(b.commit())))
                            .then();
                })
                .doOnSuccess(v -> log.info("Invalidated sessions for user {}", userId))
                .doOnError(e -> log.error("Failed to invalidate sessions for user {}", userId, e));
    }
    @Override
    public Mono<Void> invalidateUserSessions(String userId) {
        String pattern = "session:user:" + userId + ":*";
        return redisTemplate.keys(pattern)
                .flatMap(redisTemplate::delete)
                .then();
    }

    @Override
    public Mono<Void> invalidateAllSessionsForUser(Object userId) {
        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection("sessions")
                                        .whereEqualTo("userId", userId)
                                        .whereEqualTo("status", SessionStatus.ACTIVE)
                                        .get()
                        )
                )
                .flatMap(querySnapshot -> {
                    List<WriteBatch> batches = new ArrayList<>();
                    WriteBatch batch = firestore.batch();

                    int count = 0;
                    for (DocumentSnapshot document : querySnapshot.getDocuments()) {
                        batch.update(document.getReference(), "status", SessionStatus.INVALIDATED);
                        count++;

                        if (count % 500 == 0) {
                            batches.add(batch);
                            batch = firestore.batch();
                        }
                    }

                    if (count > 0) {
                        batches.add(batch);
                    }

                    return Flux.fromIterable(batches)
                            .flatMap(b -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(b.commit())))
                            .then();
                })
                .doOnSuccess(v -> log.info("Invalidated all sessions for user {}", userId))
                .doOnError(e -> log.error("Failed to invalidate sessions for user {}", userId, e));
    }

    @Override
    public Mono<Boolean> validateSession(String userId, String accessToken) {
        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection("sessions")
                                        .whereEqualTo("userId", userId)
                                        .whereEqualTo("accessToken", accessToken)
                                        .whereEqualTo("status", SessionStatus.ACTIVE)
                                        .whereGreaterThan("accessTokenExpiry", Timestamp.now()) // Fix: Use Firestore Timestamp
                                        .limit(1)
                                        .get()
                        )
                )
                .map(querySnapshot -> !querySnapshot.isEmpty())
                .flatMap(isValid -> {
                    if (!isValid) {
                        return sessionExpirationService.forceLogout(userId)
                                .thenReturn(false);
                    }
                    return Mono.just(true);
                });
    }
    @Override
    public Flux<SessionRecord> getActiveSessionsCached(String userId) {
        String redisKey = "active_sessions:" + userId;

        return sessionRecordRedisTemplate.opsForList()
                .range(redisKey, 0, -1)
                .cast(SessionRecord.class)
                .doOnNext(session -> log.debug("Cache hit: userId={}, sessionId={}", userId, mask(session.getSessionId())))
                .switchIfEmpty(
                        Flux.defer(() -> {
                            log.info("Cache miss for userId={}", userId);
                            return fetchActiveSessionsFromFirestore(userId)
                                    .flatMap(sessions -> {
                                        if (sessions.isEmpty()) {
                                            return Mono.empty();
                                        }

                                        return sessionRecordRedisTemplate.opsForList()
                                                .rightPushAll(redisKey, sessions)
                                                .then(sessionRecordRedisTemplate.expire(redisKey, ACTIVE_SESSION_TTL))
                                                .thenReturn(sessions);
                                    })
                                    .flatMapMany(Flux::fromIterable);
                        })
                )
                .onErrorResume(ex -> {
                    log.error("Error fetching sessions for userId={}", userId, ex);
                    return Flux.empty();
                });
    }
    @Override
    public Mono<List<SessionRecord>> fetchActiveSessionsFromFirestore(String userId) {
        return FirestoreUtils.apiFutureToMono(
                        firestore.collection(SESSION_COLLECTION)
                                .whereEqualTo("userId", userId)
                                .whereEqualTo("status", SessionStatus.ACTIVE.name())
                                .get()
                )
                .map(snapshot -> snapshot.getDocuments().stream()
                        .map(doc -> doc.toObject(SessionRecord.class))
                        .toList()
                );
    }

    private String mask(String value) {
        if (value == null || value.length() < 6) return "***";
        return STR."\{value.substring(0, 2)}***\{value.substring(value.length() - 2)}";
    }
    private String maskIp(String ip) {
        if (ip == null || ip.isBlank()) return "x.x.x.x";
        return ip.replaceAll("\\b(\\d{1,3})\\.(\\d{1,3})\\..*", "$1.$2.xxx.xxx");
    }

    private String maskDevice(String device) {
        if (device == null || device.length() < 5) return "****";
        return STR."\{device.substring(0, 3)}***\{device.substring(device.length() - 2)}";
    }

    private Mono<Void> fallbackAuditLog(String userId, Throwable ex) {
        AuditEventLog event = AuditEventLog.forSystemError(
                "ACTIVE_SESSION_CACHE_FAILURE",
                userId,
                Map.of("error", ex.getMessage())
        );
        return auditLogService.logEventLog(event)
                .doOnError(err -> log.warn("Failed to log fallback audit event for userId={}", userId, err))
                .onErrorResume(err -> Mono.empty()); // Prevent cascade failure
    }

    @Override
    public Mono<Void> updateSessionTokens(String userId, String newAccessToken, String newRefreshToken, String ipAddress) {
        return null;
    }

    @Override
    public Mono<Void> recordSessionActivity(String sessionId) {
        return null;
    }

    @Override
    public Mono<Void> cleanupAfterBlacklistRemoval(String encryptedIp) {
        return null;
    }

}