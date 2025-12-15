package com.techStack.authSys.service;


import com.google.cloud.firestore.*;
import com.techStack.authSys.event.BlacklistRemovedEvent;
import com.techStack.authSys.exception.RedisOperationException;
import com.techStack.authSys.repository.BlacklistService;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.repository.RateLimiterService;
import com.techStack.authSys.util.FirestoreUtil;
import com.techStack.authSys.util.SecurityContextUtils;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.context.Scope;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.apache.commons.lang3.StringUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class BlacklistServiceImpl implements BlacklistService {

    private static final String BLACKLIST_COLLECTION = "ip_blacklist";
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");
    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final RedisSecurityService redisService;
    private final JwtService jwtService;
    private final EncryptionService encryptionService;
    private final RateLimiterService.SessionService sessionService;
    private final MetricsService metricsService;
    private final ApplicationEventPublisher eventPublisher;
    private final Tracer tracer;

    private final Map<String, Boolean> blacklistCache = new ConcurrentHashMap<>();

    @Value("${security.blacklist.default-duration-hours:24}")
    private int defaultBlacklistDuration;

    @Value("${security.blacklist.cache-refresh-minutes:5}")
    private int cacheRefreshMinutes;

    @Override
    public Mono<Boolean> isBlacklisted(String ipAddress) {
        return Mono.defer(() -> {
            String encryptedIp = null;

            // Encrypt the IP address only if required (this is where the issue might be)
            try {
                encryptedIp = encryptionService.encrypt(ipAddress); // Only encrypt if needed
                //encryptedIp = ipAddress;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            // Get the blacklist status from Redis
            Boolean cachedResult = redisService.isIpBlacklisted(encryptedIp);

            return Mono.just(cachedResult);

            // Check Firestore if not found in Redis
        }).subscribeOn(Schedulers.boundedElastic());
    }
    @Override
    public Mono<Void> addToBlacklist(String ipAddress, String reason, int durationHours) {

        return Mono.fromCallable(() -> encryptionService.encrypt(ipAddress))
                .zipWith(Mono.fromCallable(() -> encryptionService.encrypt(reason)))
                .flatMap(tuple -> {
                    String encryptedIp = tuple.getT1();
                    String encryptedReason = tuple.getT2();
                    Instant expiration = Instant.now().plus(durationHours, ChronoUnit.HOURS);

                    Map<String, Object> blacklistEntry = Map.of(
                            "ipAddress", encryptedIp,
                            "reason", encryptedReason,
                            "expiration", Date.from(expiration),
                            "createdAt", FieldValue.serverTimestamp()
                    );

                    return Mono.fromFuture(
                                    FirestoreUtil.toCompletableFuture(
                                            firestore.collection(BLACKLIST_COLLECTION)
                                                    .document(encryptedIp)
                                                    .set(blacklistEntry)
                                    )
                            )
                            .thenReturn(encryptedIp) // pass the encrypted IP downstream
                            .zipWith(Mono.just(expiration));
                })
                .flatMap(tuple -> {
                    String encryptedIp = tuple.getT1();
                    Instant expiration = tuple.getT2();

                    // Write to Redis cache
                    redisService.updateBlacklistStatus(encryptedIp, true, durationHours);

                    // New revokeTokensForIp signature (userId optional here)
                    // We pass null userId because blacklisting is global by IP
                    return jwtService.revokeTokensForIp(
                            null,                         // userId
                            ipAddress,                    // raw IP
                            "SYSTEM_BLACKLIST"            // revokedBy
                    );
                })
                .doOnSuccess(v -> {
                    log.warn("IP address blacklisted: {} for {} hours. Reason: {}", ipAddress, durationHours, reason);
                    auditLogService.logSecurityEvent(
                            "IP_BLACKLISTED",
                            ipAddress,
                            "Blacklisted for " + durationHours + " hours."
                    );
                })
                .onErrorResume(e -> {
                    log.error("Failed to blacklist IP {}: {}", ipAddress, e.getMessage());
                    return Mono.error(new BlacklistOperationException("Failed to blacklist IP"));
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }


    @Override
    public Mono<Void> removeFromBlacklist(String ipAddress) {
        return Mono.defer(() -> {
                    // 1. Input validation
                    if (StringUtils.isBlank(ipAddress)) {
                        return Mono.error(new IllegalArgumentException("IP address cannot be null or empty"));
                    }

                    // 2. Start tracing
                    Span span = tracer.spanBuilder("blacklist-removal")
                            .setSpanKind(SpanKind.INTERNAL)
                            .startSpan();

                    String encryptedIp = encryptionService.encrypt(ipAddress);
                    log.debug("Starting blacklist removal process for IP: {}", ipAddress);

                    return Mono.using(
                            () -> span,
                            currentSpan -> {
                                // 3. Add tracing context
                                currentSpan.setAttribute("ip.encrypted", encryptedIp);
                                currentSpan.setAttribute("operation", "blacklist_removal");

                                return Mono.fromFuture(
                                                FirestoreUtil.toCompletableFuture(
                                                        firestore.collection(BLACKLIST_COLLECTION)
                                                                .document(encryptedIp)
                                                                .delete()
                                                )
                                        )
                                        .doOnSuccess(v -> {
                                            // 4. Parallel cleanup operations
                                            Mono<Void> redisCleanup = redisService.removeIpFromBlacklist(encryptedIp);

                                            Mono<Void> cacheCleanup = Mono.fromRunnable(() -> blacklistCache.remove(encryptedIp))
                                                    .doOnTerminate(() -> log.debug("Cache cleanup completed for {}", ipAddress)).then();

                                            Mono<Void> sessionCleanup = sessionService.cleanupAfterBlacklistRemoval(encryptedIp)
                                                    .doOnTerminate(() -> log.debug("Session cleanup completed for {}", ipAddress));

                                            // Execute cleanup operations in parallel
                                            Flux.merge(redisCleanup, cacheCleanup, sessionCleanup)
                                                    .parallel()
                                                    .runOn(Schedulers.boundedElastic())
                                                    .sequential()
                                                    .subscribe();

                                            // 5. Event publishing with context
                                            eventPublisher.publishEvent(
                                                    new BlacklistRemovedEvent(
                                                            this,
                                                            encryptedIp,
                                                            "Manual removal",
                                                            SecurityContextUtils.getCurrentUser()
                                                    )
                                            );

                                            // 6. Structured logging
                                            log.info(SECURITY_MARKER, "IP address removed from blacklist - IP: {}, Encrypted: {}, User: {}",
                                                    ipAddress, encryptedIp.substring(0, 4) + "***", SecurityContextUtils.getCurrentUser());

                                            // 7. Audit logging
                                            auditLogService.logSecurityEvent(
                                                    "BLACKLIST_REMOVAL",
                                                    ipAddress,
                                                    Map.of(
                                                            "action", "removal",
                                                            "initiator", SecurityContextUtils.getCurrentUser(),
                                                            "timestamp", Instant.now().toString()
                                                    ).toString()
                                            );

                                            // 8. Metrics
                                            metricsService.recordBlacklistEvent(
                                                    "BLACKLIST_REMOVED",
                                                    ipAddress,
                                                    Map.of(
                                                            "initiator", SecurityContextUtils.getCurrentUser(),
                                                            "method", "manual"
                                                    )
                                            );

                                            currentSpan.addEvent("blacklist.removal.success");
                                        })
                                        .doOnError(e -> {
                                            currentSpan.recordException(e);
                                            metricsService.incrementCounter("blacklist.removal.failure",
                                                    "ip", ipAddress,
                                                    "error", e.getClass().getSimpleName());
                                        })
                                        .onErrorResume(e -> {
                                            log.error(SECURITY_MARKER,
                                                    "Failed to remove IP {} from blacklist - Error: {}, StackTrace: {}",
                                                    ipAddress,
                                                    e.getMessage(),
                                                    ExceptionUtils.getStackTrace(e));
                                            return Mono.error(new BlacklistOperationException(
                                                    "Failed to remove from blacklist: " + e.getMessage()));
                                        });
                            },
                            Span::end
                    );
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then()
                .doFinally(signal -> log.debug("Blacklist removal process completed for IP: {} with signal: {}", ipAddress, signal));
    }


    @Scheduled(fixedRateString = "${security.blacklist.cleanup-rate:3600000}")
    public void cleanupExpiredEntries() {
        log.debug("Starting blacklist cleanup task");
        FirestoreUtil.toCompletableFuture(
                firestore.collection(BLACKLIST_COLLECTION)
                        .whereLessThan("expiration", new Date())
                        .get()
        ).thenAccept(querySnapshot -> {
            if (querySnapshot != null && !querySnapshot.isEmpty()) {
                WriteBatch batch = firestore.batch();
                querySnapshot.getDocuments().forEach(doc -> batch.delete(doc.getReference()));

                FirestoreUtil.toCompletableFuture(batch.commit())
                        .thenRun(() -> log.info("Cleaned up {} expired blacklist entries", querySnapshot.size()))
                        .exceptionally(e -> {
                            log.error("Failed to commit batch deletion: {}", e.getMessage());
                            return null;
                        });
            }
        }).exceptionally(throwable -> {
            log.error("Failed to clean up blacklist: {}", throwable.getMessage());
            return null;
        });
    }

    private Mono<Boolean> checkFirestoreBlacklist(String encryptedIp) {
        return Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(firestore.collection(BLACKLIST_COLLECTION).document(encryptedIp).get())
                ).map(documentSnapshot -> {
                    if (!documentSnapshot.exists()) {
                        return false;
                    }
                    Date expiration = documentSnapshot.get("expiration", Date.class);
                    if (expiration == null || expiration.after(new Date())) {
                        return true;
                    }
                    documentSnapshot.getReference().delete();
                    return false;
                })
                .onErrorResume(e -> {
                    log.error("Failed to check blacklist: {}", e.getMessage());
                    return Mono.just(false);
                });
    }
    @Override
    public Mono<Void> blacklistIp(String ipAddress) {
        String revokedBy = "SYSTEM_BLACKLIST";
        String userId = null; // you can replace this if needed

        return addToBlacklist(ipAddress, "Suspicious activity detected", defaultBlacklistDuration)
                .flatMap(v ->
                        jwtService.revokeTokensForIp(userId, ipAddress, revokedBy)
                                .then(Mono.fromRunnable(() -> {
                                    log.info("IP {} has been blacklisted.", ipAddress);
                                    auditLogService.logSecurityEvent(
                                            "IP_BLACKLISTED",
                                            ipAddress,
                                            "Added to blacklist due to suspicious activity"
                                    );
                                }))
                )
                .doOnError(e -> log.error("Failed to blacklist IP {}: {}", ipAddress, e.getMessage()))
                .then();
    }

    public static class BlacklistOperationException extends RuntimeException {
        public BlacklistOperationException(String message) {
            super(message);
        }
    }
}
