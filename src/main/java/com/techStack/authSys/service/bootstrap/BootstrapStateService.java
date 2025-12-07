package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.service.FirebaseServiceAuth;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.Map;

/**
 * Manages bootstrap completion state across Redis and Firestore.
 * Provides dual-layer persistence for reliability.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapStateService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final FirebaseServiceAuth firebaseServiceAuth;

    // Redis key for fast lookup
    private static final String REDIS_BOOTSTRAP_KEY = "bootstrap:super_admin:completed";
    private static final Duration REDIS_TTL = Duration.ofDays(730); // 2 years

    // Firestore collection for persistent storage
    private static final String FIRESTORE_COLLECTION = "system_flags";
    private static final String FIRESTORE_DOCUMENT = "bootstrap_admin";

    private static final Duration WAIT_POLL_INTERVAL = Duration.ofSeconds(2);
    private static final Duration WAIT_TIMEOUT = Duration.ofMinutes(5);

    /**
     * Checks if bootstrap has been completed.
     * Uses Redis for fast lookup, falls back to Firestore.
     *
     * @return true if bootstrap is complete, false otherwise
     */
    public Mono<Boolean> isBootstrapCompleted() {
        return checkRedisState()
                .flatMap(redisCompleted -> {
                    if (redisCompleted) {
                        log.debug("✅ Bootstrap state found in Redis cache");
                        return Mono.just(true);
                    }

                    // Redis cache miss - check Firestore
                    log.debug("⚠️ Redis cache miss - checking Firestore");
                    return checkFirestoreState()
                            .doOnNext(firestoreCompleted -> {
                                if (firestoreCompleted) {
                                    // Backfill Redis cache
                                    backfillRedisCache();
                                }
                            });
                })
                .onErrorResume(e -> {
                    log.error("❌ Error checking bootstrap state: {}", e.getMessage());
                    return Mono.just(false); // Fail-safe: assume not completed
                });
    }

    /**
     * Marks bootstrap as completed in both Redis and Firestore.
     */
    public Mono<Void> markBootstrapComplete() {
        log.info("💾 Marking bootstrap as complete in both Redis and Firestore");

        return saveToFirestore()
                .then(saveToRedis())
                .doOnSuccess(v -> log.info("✅ Bootstrap completion state persisted"))
                .doOnError(e -> log.error("❌ Failed to mark bootstrap complete: {}",
                        e.getMessage(), e));
    }

    /**
     * Waits for another instance to complete bootstrap.
     * Polls every 2 seconds with a 5-minute timeout.
     */
    public Mono<Void> waitForBootstrapCompletion() {
        log.info("⏳ Waiting for bootstrap completion by another instance...");

        return isBootstrapCompleted()
                .filter(Boolean::booleanValue)
                .repeatWhenEmpty(flux ->
                        flux.delayElements(WAIT_POLL_INTERVAL)
                                .doOnNext(i -> log.debug("Polling bootstrap state... attempt {}", i + 1))
                )
                .timeout(WAIT_TIMEOUT, Mono.defer(() -> {
                    log.warn("⏰ Bootstrap wait timeout exceeded");
                    return Mono.error(new RuntimeException("Bootstrap wait timeout"));
                }))
                .doOnSuccess(v -> log.info("✅ Bootstrap completed by another instance"))
                .then();
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    /**
     * Checks Redis for bootstrap completion flag.
     */
    private Mono<Boolean> checkRedisState() {
        return Mono.fromCallable(() ->
                        Boolean.TRUE.equals(redisTemplate.hasKey(REDIS_BOOTSTRAP_KEY))
                )
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorReturn(false);
    }

    /**
     * Checks Firestore for bootstrap completion flag.
     */
    private Mono<Boolean> checkFirestoreState() {
        return firebaseServiceAuth.getDocument(FIRESTORE_COLLECTION, FIRESTORE_DOCUMENT)
                .map(doc -> doc.containsKey("completed") &&
                        Boolean.TRUE.equals(doc.get("completed")))
                .defaultIfEmpty(false);
    }

    /**
     * Saves bootstrap completion to Firestore.
     */
    private Mono<Void> saveToFirestore() {
        Map<String, Object> data = Map.of(
                "completed", true,
                "timestamp", System.currentTimeMillis(),
                "version", "1.0"
        );

        return firebaseServiceAuth.setDocument(FIRESTORE_COLLECTION, FIRESTORE_DOCUMENT, data)
                .doOnSuccess(v -> log.debug("✅ Bootstrap state saved to Firestore"))
                .doOnError(e -> log.error("❌ Failed to save to Firestore: {}", e.getMessage()));
    }

    /**
     * Saves bootstrap completion to Redis.
     */
    private Mono<Void> saveToRedis() {
        return Mono.fromRunnable(() ->
                        redisTemplate.opsForValue().set(REDIS_BOOTSTRAP_KEY, true, REDIS_TTL)
                )
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> log.debug("✅ Bootstrap state cached in Redis"))
                .doOnError(e -> log.error("❌ Failed to cache in Redis: {}", e.getMessage()))
                .then();
    }

    /**
     * Backfills Redis cache when Firestore has the state but Redis doesn't.
     */
    private void backfillRedisCache() {
        try {
            redisTemplate.opsForValue().set(REDIS_BOOTSTRAP_KEY, true, REDIS_TTL);
            log.debug("🔄 Backfilled Redis cache from Firestore state");
        } catch (Exception e) {
            log.warn("⚠️ Failed to backfill Redis cache: {}", e.getMessage());
        }
    }
}
