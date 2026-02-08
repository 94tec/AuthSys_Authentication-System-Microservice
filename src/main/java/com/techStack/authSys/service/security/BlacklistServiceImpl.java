package com.techStack.authSys.service.security;

import com.google.cloud.firestore.*;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.repository.sucurity.BlacklistService;
import com.techStack.authSys.service.events.EventPublisherService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.util.auth.SecurityContextUtils;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import com.techStack.authSys.util.validation.HelperUtils;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.Tracer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Blacklist Service Implementation
 *
 * Manages IP address blacklisting with Clock-based timestamp tracking.
 * Includes Redis caching, Firestore persistence, and comprehensive audit logging.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BlacklistServiceImpl implements BlacklistService {

    /* =========================
       Constants
       ========================= */

    private static final String BLACKLIST_COLLECTION = "ip_blacklist";
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    /* =========================
       Dependencies
       ========================= */

    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final RedisSecurityService redisService;
    private final JwtService jwtService;
    private final EncryptionService encryptionService;
    private final SessionService sessionService;
    private final MetricsService metricsService;
    private final EventPublisherService eventPublisherService;
    private final Tracer tracer;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${security.blacklist.default-duration-hours:24}")
    private int defaultBlacklistDuration;

    @Value("${security.blacklist.cache-refresh-minutes:5}")
    private int cacheRefreshMinutes;

    /* =========================
       Cache
       ========================= */

    private final Map<String, Boolean> blacklistCache = new ConcurrentHashMap<>();

    /* =========================
       Blacklist Check
       ========================= */

    /**
     * Check if IP address is blacklisted
     */
    @Override
    public Mono<Boolean> isBlacklisted(String ipAddress) {
        Instant checkStart = clock.instant();

        return Mono.defer(() -> {
            try {
                String encryptedIp = encryptionService.encrypt(ipAddress);

                // Check Redis cache first
                Boolean cachedResult = redisService.isIpBlacklisted(encryptedIp);

                if (cachedResult != null) {
                    Instant cacheHitTime = clock.instant();
                    Duration duration = Duration.between(checkStart, cacheHitTime);

                    log.debug("Cache HIT at {} in {} for IP: {} - Blacklisted: {}",
                            cacheHitTime, duration,
                            HelperUtils.maskIpAddress(ipAddress),
                            cachedResult);

                    return Mono.just(cachedResult);
                }

                // Cache miss - check Firestore
                Instant cacheMissTime = clock.instant();
                log.debug("Cache MISS at {} for IP: {} - checking Firestore",
                        cacheMissTime, HelperUtils.maskIpAddress(ipAddress));

                return checkFirestoreBlacklist(encryptedIp, ipAddress, checkStart)
                        .doOnSuccess(result -> {
                            // Update Redis cache
                            redisService.updateBlacklistStatus(encryptedIp, result, cacheRefreshMinutes * 60);
                        });

            } catch (Exception e) {
                Instant errorTime = clock.instant();
                log.error("❌ Blacklist check failed at {} for IP {}: {}",
                        errorTime, HelperUtils.maskIpAddress(ipAddress), e.getMessage());
                return Mono.error(new RuntimeException("Failed to check blacklist", e));
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Check Firestore for blacklist status
     */
    private Mono<Boolean> checkFirestoreBlacklist(
            String encryptedIp,
            String rawIp,
            Instant checkStart) {

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(BLACKLIST_COLLECTION)
                                        .document(encryptedIp)
                                        .get()
                        )
                )
                .flatMap(documentSnapshot -> {
                    Instant checkEnd = clock.instant();
                    Duration duration = Duration.between(checkStart, checkEnd);

                    if (!documentSnapshot.exists()) {
                        log.debug("IP not blacklisted at {} (checked in {}): {}",
                                checkEnd, duration, HelperUtils.maskIpAddress(rawIp));
                        return Mono.just(false);
                    }

                    Date expiration = documentSnapshot.get("expiration", Date.class);
                    Instant now = clock.instant();

                    if (expiration == null || expiration.after(Date.from(now))) {
                        log.warn("🚨 IP IS blacklisted at {} (expires: {}): {}",
                                checkEnd, expiration, HelperUtils.maskIpAddress(rawIp));
                        return Mono.just(true);
                    }

                    // Entry expired - delete it
                    log.info("Blacklist entry expired at {} for IP: {} - deleting",
                            checkEnd, HelperUtils.maskIpAddress(rawIp));

                    return Mono.fromFuture(
                                    FirestoreUtil.toCompletableFuture(
                                            documentSnapshot.getReference().delete()
                                    )
                            )
                            .thenReturn(false);
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Firestore blacklist check failed at {} for IP {}: {}",
                            errorTime, HelperUtils.maskIpAddress(rawIp), e.getMessage());
                    return Mono.just(false);
                });
    }

    /* =========================
       Add to Blacklist
       ========================= */

    /**
     * Add IP address to blacklist
     */
    @Override
    public Mono<Void> addToBlacklist(String ipAddress, String reason, int durationHours) {
        Instant blacklistStart = clock.instant();

        log.warn("🚨 Adding IP to blacklist at {} - IP: {} | Reason: {} | Duration: {}h",
                blacklistStart,
                HelperUtils.maskIpAddress(ipAddress),
                reason,
                durationHours);

        return Mono.fromCallable(() -> encryptionService.encrypt(ipAddress))
                .zipWith(Mono.fromCallable(() -> encryptionService.encrypt(reason)))
                .flatMap(tuple -> {
                    String encryptedIp = tuple.getT1();
                    String encryptedReason = tuple.getT2();
                    Instant expiration = blacklistStart.plus(durationHours, ChronoUnit.HOURS);

                    Map<String, Object> blacklistEntry = Map.of(
                            "ipAddress", encryptedIp,
                            "reason", encryptedReason,
                            "expiration", Date.from(expiration),
                            "createdAt", FieldValue.serverTimestamp(),
                            "blacklistedAt", blacklistStart.toString(),
                            "blacklistedAtMillis", blacklistStart.toEpochMilli()
                    );

                    return saveBlacklistEntry(encryptedIp, blacklistEntry, blacklistStart)
                            .thenReturn(new BlacklistData(encryptedIp, expiration, durationHours));
                })
                .flatMap(data -> updateCacheAndRevokeTokens(
                        data.encryptedIp,
                        data.expiration,
                        data.durationHours,
                        ipAddress,
                        blacklistStart
                ))
                .doOnSuccess(v -> {
                    Instant blacklistEnd = clock.instant();
                    Duration duration = Duration.between(blacklistStart, blacklistEnd);

                    log.warn("✅ IP blacklisted successfully at {} in {} - IP: {} | Duration: {}h",
                            blacklistEnd,
                            duration,
                            HelperUtils.maskIpAddress(ipAddress),
                            durationHours);

                    auditLogService.logSecurityEvent(
                            "IP_BLACKLISTED",
                            ipAddress,
                            String.format("Blacklisted at %s for %d hours - Reason: %s",
                                    blacklistEnd, durationHours, reason)
                    );

                    // ✅ FIXED - All values as String
                    metricsService.recordBlacklistEvent(
                            "IP_BLACKLISTED",
                            ipAddress,
                            Map.of(
                                    "duration_hours", String.valueOf(durationHours),
                                    "reason", reason,
                                    "timestamp", blacklistEnd.toString(),
                                    "duration_ms", String.valueOf(duration.toMillis())
                            )
                    );
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(blacklistStart, errorTime);

                    log.error("❌ Failed to blacklist IP at {} after {} - IP: {}: {}",
                            errorTime,
                            duration,
                            HelperUtils.maskIpAddress(ipAddress),
                            e.getMessage(),
                            e);

                    return Mono.error(new BlacklistOperationException(
                            "Failed to blacklist IP: " + e.getMessage()
                    ));
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Save blacklist entry to Firestore
     */
    private Mono<Void> saveBlacklistEntry(
            String encryptedIp,
            Map<String, Object> blacklistEntry,
            Instant startTime) {

        Instant saveStart = clock.instant();

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(BLACKLIST_COLLECTION)
                                        .document(encryptedIp)
                                        .set(blacklistEntry)
                        )
                )
                .doOnSuccess(v -> {
                    Instant saveEnd = clock.instant();
                    Duration duration = Duration.between(saveStart, saveEnd);

                    log.debug("Blacklist entry saved at {} in {}", saveEnd, duration);
                })
                .then();
    }

    /**
     * Update cache and revoke tokens
     */
    private Mono<Void> updateCacheAndRevokeTokens(
            String encryptedIp,
            Instant expiration,
            int durationHours,
            String ipAddress,
            Instant blacklistStart) {

        Instant cacheUpdateStart = clock.instant();

        // Update Redis cache
        redisService.updateBlacklistStatus(encryptedIp, true, durationHours);

        log.debug("Redis cache updated at {} for IP: {}",
                clock.instant(), HelperUtils.maskIpAddress(ipAddress));

        // Revoke all tokens for this IP
        return jwtService.revokeTokensForIp(null, ipAddress, "SYSTEM_BLACKLIST")
                .doOnSuccess(v -> {
                    Instant revokeEnd = clock.instant();
                    Duration duration = Duration.between(cacheUpdateStart, revokeEnd);

                    log.info("Tokens revoked at {} in {} for IP: {}",
                            revokeEnd, duration, HelperUtils.maskIpAddress(ipAddress));
                });
    }

    /* =========================
       Remove from Blacklist
       ========================= */

    /**
     * Remove IP address from blacklist
     */
    @Override
    public Mono<Void> removeFromBlacklist(String ipAddress) {
        Instant removalStart = clock.instant();

        return Mono.defer(() -> {
                    // 1. Input validation
                    if (StringUtils.isBlank(ipAddress)) {
                        return Mono.error(new IllegalArgumentException("IP address cannot be null or empty"));
                    }

                    // 2. Start tracing
                    Span span = tracer.spanBuilder("blacklist-removal")
                            .setSpanKind(SpanKind.INTERNAL)
                            .startSpan();

                    log.info("Removing IP from blacklist at {} - IP: {}",
                            removalStart, HelperUtils.maskIpAddress(ipAddress));

                    String encryptedIp = encryptionService.encrypt(ipAddress);

                    return Mono.using(
                            () -> span,
                            currentSpan -> {
                                // 3. Add tracing context
                                currentSpan.setAttribute("ip.encrypted", encryptedIp.substring(0, 8) + "...");
                                currentSpan.setAttribute("operation", "blacklist_removal");
                                currentSpan.setAttribute("timestamp", removalStart.toString());

                                return deleteFromFirestore(encryptedIp, ipAddress, removalStart, currentSpan)
                                        .flatMap(v -> performCleanupOperations(
                                                encryptedIp,
                                                ipAddress,
                                                removalStart
                                        ))
                                        .doOnSuccess(v -> {
                                            Instant removalEnd = clock.instant();
                                            Duration duration = Duration.between(removalStart, removalEnd);

                                            log.info(SECURITY_MARKER,
                                                    "✅ IP removed from blacklist at {} in {} - IP: {} | User: {}",
                                                    removalEnd,
                                                    duration,
                                                    HelperUtils.maskIpAddress(ipAddress),
                                                    SecurityContextUtils.getCurrentUser());

                                            currentSpan.addEvent("blacklist.removal.success");

                                            // Publish event
                                            eventPublisherService.publishBlacklistRemoved(
                                                    encryptedIp,
                                                    "Manual removal from blacklist",           // ✅ reason parameter
                                                    SecurityContextUtils.getCurrentUser()      // ✅ removedBy parameter
                                            );

                                            // Audit log
                                            auditLogService.logSecurityEvent(
                                                    "BLACKLIST_REMOVAL",
                                                    ipAddress,
                                                    String.format("Removed at %s by %s",
                                                            removalEnd,
                                                            SecurityContextUtils.getCurrentUser())
                                            );

                                            // ✅ FIXED - All values as String
                                            metricsService.recordBlacklistEvent(
                                                    "BLACKLIST_REMOVED",
                                                    ipAddress,
                                                    Map.of(
                                                            "initiator", SecurityContextUtils.getCurrentUser(),
                                                            "timestamp", removalEnd.toString(),
                                                            "duration_ms", String.valueOf(duration.toMillis())
                                                    )
                                            );
                                        })
                                        .doOnError(e -> {
                                            Instant errorTime = clock.instant();
                                            Duration duration = Duration.between(removalStart, errorTime);

                                            currentSpan.recordException(e);

                                            log.error(SECURITY_MARKER,
                                                    "❌ Failed to remove IP from blacklist at {} after {} - IP: {} | Error: {}",
                                                    errorTime,
                                                    duration,
                                                    HelperUtils.maskIpAddress(ipAddress),
                                                    e.getMessage(),
                                                    e);

                                            metricsService.incrementCounter(
                                                    "blacklist.removal.failure",
                                                    "ip", HelperUtils.maskIpAddress(ipAddress),
                                                    "error", e.getClass().getSimpleName()
                                            );
                                        })
                                        .onErrorResume(e -> Mono.error(
                                                new BlacklistOperationException(
                                                        "Failed to remove from blacklist: " + e.getMessage()
                                                )
                                        ));
                            },
                            Span::end
                    );
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then()
                .doFinally(signal -> {
                    Instant finalTime = clock.instant();
                    log.debug("Blacklist removal process completed at {} with signal: {}",
                            finalTime, signal);
                });
    }

    /**
     * Delete from Firestore
     */
    private Mono<Void> deleteFromFirestore(
            String encryptedIp,
            String rawIp,
            Instant startTime,
            Span span) {

        Instant deleteStart = clock.instant();

        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(
                                firestore.collection(BLACKLIST_COLLECTION)
                                        .document(encryptedIp)
                                        .delete()
                        )
                )
                .doOnSuccess(v -> {
                    Instant deleteEnd = clock.instant();
                    Duration duration = Duration.between(deleteStart, deleteEnd);

                    log.debug("Deleted from Firestore at {} in {} for IP: {}",
                            deleteEnd, duration, HelperUtils.maskIpAddress(rawIp));

                    span.addEvent("firestore.delete.success");
                })
                .then();
    }

    /**
     * Perform cleanup operations
     */
    private Mono<Void> performCleanupOperations(
            String encryptedIp,
            String rawIp,
            Instant startTime) {

        Instant cleanupStart = clock.instant();

        log.debug("Starting cleanup operations at {} for IP: {}",
                cleanupStart, HelperUtils.maskIpAddress(rawIp));

        // Parallel cleanup operations
        Mono<Void> redisCleanup = redisService.removeIpFromBlacklist(encryptedIp)
                .doOnSuccess(v -> log.debug("Redis cleanup completed at {} for IP: {}",
                        clock.instant(), HelperUtils.maskIpAddress(rawIp)));

        Mono<Void> cacheCleanup = Mono.fromRunnable(() -> blacklistCache.remove(encryptedIp))
                .doOnTerminate(() -> log.debug("Cache cleanup completed at {} for IP: {}",
                        clock.instant(), HelperUtils.maskIpAddress(rawIp)))
                .then();

        Mono<Void> sessionCleanup = sessionService.cleanupAfterBlacklistRemoval(encryptedIp)
                .doOnTerminate(() -> log.debug("Session cleanup completed at {} for IP: {}",
                        clock.instant(), HelperUtils.maskIpAddress(rawIp)));

        return Flux.merge(redisCleanup, cacheCleanup, sessionCleanup)
                .parallel()
                .runOn(Schedulers.boundedElastic())
                .sequential()
                .then()
                .doOnSuccess(v -> {
                    Instant cleanupEnd = clock.instant();
                    Duration duration = Duration.between(cleanupStart, cleanupEnd);

                    log.info("✅ All cleanup operations completed at {} in {}",
                            cleanupEnd, duration);
                });
    }

    /* =========================
       Quick Blacklist
       ========================= */

    /**
     * Blacklist IP with default settings
     */
    @Override
    public Mono<Void> blacklistIp(String ipAddress) {
        Instant blacklistStart = clock.instant();
        String revokedBy = "SYSTEM_BLACKLIST";

        log.warn("🚨 Quick blacklist initiated at {} for IP: {}",
                blacklistStart, HelperUtils.maskIpAddress(ipAddress));

        return addToBlacklist(ipAddress, "Suspicious activity detected", defaultBlacklistDuration)
                .flatMap(v -> jwtService.revokeTokensForIp(null, ipAddress, revokedBy))
                .doOnSuccess(v -> {
                    Instant blacklistEnd = clock.instant();
                    Duration duration = Duration.between(blacklistStart, blacklistEnd);

                    log.info("✅ IP blacklisted at {} in {} - IP: {}",
                            blacklistEnd, duration, HelperUtils.maskIpAddress(ipAddress));

                    auditLogService.logSecurityEvent(
                            "IP_BLACKLISTED",
                            ipAddress,
                            "Quick blacklist due to suspicious activity at " + blacklistEnd
                    );
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Quick blacklist failed at {} for IP {}: {}",
                            errorTime, HelperUtils.maskIpAddress(ipAddress), e.getMessage());
                })
                .then();
    }

    /* =========================
       Scheduled Cleanup
       ========================= */

    /**
     * Cleanup expired blacklist entries (runs hourly)
     */
    @Scheduled(fixedRateString = "${security.blacklist.cleanup-rate:3600000}")
    public void cleanupExpiredEntries() {
        Instant cleanupStart = clock.instant();

        log.info("Starting scheduled blacklist cleanup at {}", cleanupStart);

        FirestoreUtil.toCompletableFuture(
                        firestore.collection(BLACKLIST_COLLECTION)
                                .whereLessThan("expiration", Date.from(cleanupStart))
                                .get()
                )
                .thenAccept(querySnapshot -> {
                    if (querySnapshot != null && !querySnapshot.isEmpty()) {
                        int count = querySnapshot.size();

                        WriteBatch batch = firestore.batch();
                        querySnapshot.getDocuments()
                                .forEach(doc -> batch.delete(doc.getReference()));

                        FirestoreUtil.toCompletableFuture(batch.commit())
                                .thenRun(() -> {
                                    Instant cleanupEnd = clock.instant();
                                    Duration duration = Duration.between(cleanupStart, cleanupEnd);

                                    log.info("✅ Cleaned up {} expired blacklist entries at {} in {}",
                                            count, cleanupEnd, duration);

                                    // ✅ FIXED - All values as String
                                    metricsService.recordBlacklistEvent(
                                            "CLEANUP_EXPIRED",
                                            "scheduled",
                                            Map.of(
                                                    "count", String.valueOf(count),
                                                    "timestamp", cleanupEnd.toString(),
                                                    "duration_ms", String.valueOf(duration.toMillis())
                                            )
                                    );
                                })
                                .exceptionally(e -> {
                                    Instant errorTime = clock.instant();
                                    log.error("❌ Batch deletion failed at {}: {}",
                                            errorTime, e.getMessage());
                                    return null;
                                });
                    } else {
                        Instant noEntriesTime = clock.instant();
                        log.debug("No expired blacklist entries found at {}", noEntriesTime);
                    }
                })
                .exceptionally(throwable -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Cleanup failed at {}: {}", errorTime, throwable.getMessage());
                    return null;
                });
    }

    /* =========================
       Helper Classes
       ========================= */

    /**
     * Blacklist data holder
     */
    private record BlacklistData(
            String encryptedIp,
            Instant expiration,
            int durationHours
    ) {
    }

    /**
     * Blacklist operation exception
     */
    public static class BlacklistOperationException extends RuntimeException {
        public BlacklistOperationException(String message) {
            super(message);
        }
    }
}