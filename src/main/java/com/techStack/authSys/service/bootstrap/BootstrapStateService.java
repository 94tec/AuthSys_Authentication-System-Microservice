package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Bootstrap State Service
 *
 * Manages bootstrap completion state across Redis and Firestore.
 * Uses Clock for consistent timestamp tracking.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapStateService {

    /* =========================
       Dependencies
       ========================= */

    private final RedisTemplate<String, Object> redisTemplate;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    private static final String REDIS_BOOTSTRAP_KEY = "bootstrap:super_admin:completed";
    private static final Duration REDIS_TTL = Duration.ofDays(730); // 2 years

    private static final String FIRESTORE_COLLECTION = "system_flags";
    private static final String FIRESTORE_DOCUMENT = "bootstrap_admin";

    private static final Duration WAIT_POLL_INTERVAL = Duration.ofSeconds(2);
    private static final Duration WAIT_TIMEOUT = Duration.ofMinutes(5);

    /* =========================
       State Checking
       ========================= */

    /**
     * Check if bootstrap has been completed
     * Uses Redis for fast lookup, falls back to Firestore
     */
    public Mono<Boolean> isBootstrapCompleted() {
        Instant now = clock.instant();

        return checkRedisState()
                .flatMap(redisCompleted -> {
                    if (redisCompleted) {
                        log.debug("✅ Bootstrap state found in Redis cache at {}", now);
                        return Mono.just(true);
                    }

                    // Redis cache miss - check Firestore
                    log.debug("⚠️ Redis cache miss at {} - checking Firestore", now);
                    return checkFirestoreState()
                            .doOnNext(firestoreCompleted -> {
                                if (firestoreCompleted) {
                                    backfillRedisCache(now);
                                }
                            });
                })
                .onErrorResume(e -> {
                    log.error("❌ Error checking bootstrap state at {}: {}",
                            now, e.getMessage());
                    return Mono.just(false); // Fail-safe: assume not completed
                });
    }

    /**
     * Check Redis for bootstrap completion flag
     */
    private Mono<Boolean> checkRedisState() {
        return Mono.fromCallable(() ->
                        Boolean.TRUE.equals(redisTemplate.hasKey(REDIS_BOOTSTRAP_KEY))
                )
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorReturn(false);
    }

    /**
     * Check Firestore for bootstrap completion flag
     */
    private Mono<Boolean> checkFirestoreState() {
        return firebaseServiceAuth.getDocument(FIRESTORE_COLLECTION, FIRESTORE_DOCUMENT)
                .map(doc -> doc.containsKey("completed") &&
                        Boolean.TRUE.equals(doc.get("completed")))
                .defaultIfEmpty(false);
    }

    /* =========================
       State Persistence
       ========================= */

    /**
     * Mark bootstrap as completed in both Redis and Firestore
     */
    public Mono<Void> markBootstrapComplete() {
        Instant now = clock.instant();

        log.info("💾 Marking bootstrap as complete at {}", now);

        return saveToFirestore(now)
                .then(saveToRedis(now))
                .doOnSuccess(v -> log.info("✅ Bootstrap completion state persisted at {}", now))
                .doOnError(e -> log.error("❌ Failed to mark bootstrap complete at {}: {}",
                        now, e.getMessage(), e));
    }

    /**
     * Save bootstrap completion to Firestore
     */
    private Mono<Void> saveToFirestore(Instant timestamp) {
        Map<String, Object> data = Map.of(
                "completed", true,
                "timestamp", timestamp.toEpochMilli(),
                "timestampIso", timestamp.toString(),
                "version", "1.0"
        );

        return firebaseServiceAuth.setDocument(FIRESTORE_COLLECTION, FIRESTORE_DOCUMENT, data)
                .doOnSuccess(v -> log.debug("✅ Bootstrap state saved to Firestore at {}",
                        timestamp))
                .doOnError(e -> log.error("❌ Failed to save to Firestore at {}: {}",
                        timestamp, e.getMessage()));
    }

    /**
     * Save bootstrap completion to Redis
     */
    private Mono<Void> saveToRedis(Instant timestamp) {
        return Mono.fromRunnable(() ->
                        redisTemplate.opsForValue().set(REDIS_BOOTSTRAP_KEY, true, REDIS_TTL)
                )
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> log.debug("✅ Bootstrap state cached in Redis at {}",
                        timestamp))
                .doOnError(e -> log.error("❌ Failed to cache in Redis at {}: {}",
                        timestamp, e.getMessage()))
                .then();
    }

    /* =========================
       Waiting & Polling
       ========================= */

    /**
     * Wait for another instance to complete bootstrap
     * Polls every 2 seconds with a 5-minute timeout
     */
    public Mono<Void> waitForBootstrapCompletion() {
        Instant startTime = clock.instant();

        log.info("⏳ Waiting for bootstrap completion by another instance at {}", startTime);

        return isBootstrapCompleted()
                .filter(Boolean::booleanValue)
                .repeatWhenEmpty(flux ->
                        flux.delayElements(WAIT_POLL_INTERVAL)
                                .doOnNext(i -> {
                                    Instant now = clock.instant();
                                    Duration elapsed = Duration.between(startTime, now);
                                    log.debug("Polling bootstrap state at {} (elapsed: {}, attempt: {})",
                                            now, elapsed, i + 1);
                                })
                )
                .timeout(WAIT_TIMEOUT, Mono.defer(() -> {
                    Instant now = clock.instant();
                    Duration totalWait = Duration.between(startTime, now);
                    log.warn("⏰ Bootstrap wait timeout exceeded at {} (waited: {})",
                            now, totalWait);
                    return Mono.error(new RuntimeException("Bootstrap wait timeout"));
                }))
                .doOnSuccess(v -> {
                    Instant endTime = clock.instant();
                    Duration totalWait = Duration.between(startTime, endTime);
                    log.info("✅ Bootstrap completed by another instance at {} (waited: {})",
                            endTime, totalWait);
                })
                .then();
    }

    /* =========================
       State Reset
       ========================= */

    /**
     * Reset bootstrap state in both Redis and Firestore
     * USE ONLY for development or recovery scenarios
     */
    public Mono<Void> resetBootstrapState() {
        Instant now = clock.instant();

        log.warn("🔄 Resetting bootstrap state at {} - Redis and Firestore", now);

        return Mono.fromRunnable(() -> {
                    if (redisTemplate.hasKey(REDIS_BOOTSTRAP_KEY)) {
                        redisTemplate.delete(REDIS_BOOTSTRAP_KEY);
                        log.debug("✅ Redis bootstrap key deleted at {}", now);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then(firebaseServiceAuth.deleteDocument(FIRESTORE_COLLECTION, FIRESTORE_DOCUMENT))
                .doOnSuccess(v -> log.info("✅ Bootstrap state fully reset at {}", now))
                .doOnError(e -> log.error("❌ Failed to reset bootstrap state at {}: {}",
                        now, e.getMessage(), e));
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Backfill Redis cache when Firestore has the state but Redis doesn't
     */
    private void backfillRedisCache(Instant timestamp) {
        try {
            redisTemplate.opsForValue().set(REDIS_BOOTSTRAP_KEY, true, REDIS_TTL);
            log.debug("🔄 Backfilled Redis cache from Firestore state at {}", timestamp);
        } catch (Exception e) {
            log.warn("⚠️ Failed to backfill Redis cache at {}: {}",
                    timestamp, e.getMessage());
        }
    }
}