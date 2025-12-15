package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.service.RedisUserCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Manages distributed locking for bootstrap operations with stale lock detection.
 * Ensures only one instance can perform bootstrap at a time.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapLockService {

    private final RedisUserCacheService redisCacheService;
    private final RedisTemplate<String, Object> redisTemplate;

    private static final String LOCK_KEY = "bootstrap:lock";
    private static final String LOCK_TIMESTAMP_KEY = "bootstrap:lock:timestamp";
    private static final Duration LOCK_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration STALE_LOCK_THRESHOLD = Duration.ofMinutes(10); // Double the timeout

    /**
     * Attempts to acquire the bootstrap lock with stale lock detection.
     *
     * @return true if lock acquired, false if held by active instance
     */
    public Mono<Boolean> acquireBootstrapLock() {
        return checkAndClearStaleLock()
                .flatMap(staleCleared -> {
                    if (staleCleared) {
                        log.warn("🧹 Cleared stale bootstrap lock");
                    }
                    return attemptLockAcquisition();
                })
                .onErrorResume(e -> {
                    log.warn("⚠️ Failed to acquire bootstrap lock: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Checks for and clears stale locks.
     */
    private Mono<Boolean> checkAndClearStaleLock() {
        return Mono.fromCallable(() -> {
            try {
                // Check if lock exists
                Boolean lockExists = redisTemplate.hasKey(LOCK_KEY);
                if (!Boolean.TRUE.equals(lockExists)) {
                    return false; // No lock to clear
                }

                // Get lock timestamp
                Long timestamp = (Long) redisTemplate.opsForValue().get(LOCK_TIMESTAMP_KEY);
                if (timestamp == null) {
                    // Lock exists but no timestamp - assume stale
                    log.warn("⚠️ Found lock without timestamp - clearing as stale");
                    redisTemplate.delete(LOCK_KEY);
                    redisTemplate.delete(LOCK_TIMESTAMP_KEY);
                    return true;
                }

                // Check if lock is stale
                Instant lockTime = Instant.ofEpochMilli(timestamp);
                Instant now = Instant.now();
                Duration lockAge = Duration.between(lockTime, now);

                if (lockAge.compareTo(STALE_LOCK_THRESHOLD) > 0) {
                    log.warn("⚠️ Found stale lock (age: {} minutes) - clearing",
                            lockAge.toMinutes());
                    redisTemplate.delete(LOCK_KEY);
                    redisTemplate.delete(LOCK_TIMESTAMP_KEY);
                    return true;
                }

                return false; // Lock is fresh, leave it
            } catch (Exception e) {
                log.error("Error checking for stale lock: {}", e.getMessage());
                return false;
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Attempts to acquire the lock.
     */
    private Mono<Boolean> attemptLockAcquisition() {
        String lockValue = generateLockValue();
        long timestamp = Instant.now().toEpochMilli();

        return Mono.fromCallable(() -> {
            // Try to acquire lock
            Boolean acquired = redisTemplate.opsForValue()
                    .setIfAbsent(LOCK_KEY, lockValue, LOCK_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);

            if (Boolean.TRUE.equals(acquired)) {
                // Set timestamp for stale lock detection
                redisTemplate.opsForValue().set(
                        LOCK_TIMESTAMP_KEY,
                        timestamp,
                        LOCK_TIMEOUT.toMillis(),
                        TimeUnit.MILLISECONDS
                );

                log.info("🔒 Bootstrap lock acquired (timeout: {})", LOCK_TIMEOUT);
                return true;
            }

            log.info("⏳ Bootstrap lock already held by another instance");
            return false;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Releases the bootstrap lock and its timestamp.
     */
    public void releaseBootstrapLock() {
        try {
            redisTemplate.delete(LOCK_KEY);
            redisTemplate.delete(LOCK_TIMESTAMP_KEY);
            log.info("🔓 Bootstrap lock released");
        } catch (Exception e) {
            log.warn("⚠️ Failed to release bootstrap lock: {}", e.getMessage());
        }
    }

    /**
     * Forces release of the bootstrap lock (for manual intervention).
     * USE WITH CAUTION - only call this if you're certain no instance is running bootstrap.
     */
    public Mono<Void> forceReleaseLock() {
        return Mono.fromRunnable(() -> {
            try {
                Boolean lockExisted = redisTemplate.hasKey(LOCK_KEY);
                Boolean timestampExisted = redisTemplate.hasKey(LOCK_TIMESTAMP_KEY);

                redisTemplate.delete(LOCK_KEY);
                redisTemplate.delete(LOCK_TIMESTAMP_KEY);

                if (Boolean.TRUE.equals(lockExisted)) {
                    log.warn("⚠️ FORCED release of bootstrap lock");
                }
                if (Boolean.TRUE.equals(timestampExisted)) {
                    log.warn("⚠️ FORCED removal of lock timestamp");
                }
            } catch (Exception e) {
                log.error("Failed to force release lock: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Gets lock status information for debugging.
     */
    public Mono<LockStatus> getLockStatus() {
        return Mono.fromCallable(() -> {
            LockStatus status = new LockStatus();

            try {
                status.exists = Boolean.TRUE.equals(redisTemplate.hasKey(LOCK_KEY));

                if (status.exists) {
                    Long timestamp = (Long) redisTemplate.opsForValue().get(LOCK_TIMESTAMP_KEY);
                    if (timestamp != null) {
                        status.acquiredAt = Instant.ofEpochMilli(timestamp);
                        status.age = Duration.between(status.acquiredAt, Instant.now());
                        status.isStale = status.age.compareTo(STALE_LOCK_THRESHOLD) > 0;
                    }

                    // Get TTL
                    Long ttl = redisTemplate.getExpire(LOCK_KEY, TimeUnit.SECONDS);
                    if (ttl != null && ttl > 0) {
                        status.ttl = Duration.ofSeconds(ttl);
                    }
                }
            } catch (Exception e) {
                log.error("Error getting lock status: {}", e.getMessage());
            }

            return status;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Generates a unique lock value for this instance.
     */
    private String generateLockValue() {
        return String.format("%s-%d-%s",
                Thread.currentThread().getName(),
                Instant.now().toEpochMilli(),
                java.util.UUID.randomUUID().toString().substring(0, 8)
        );
    }

    /**
     * Lock status information
     */
    public static class LockStatus {
        public boolean exists;
        public Instant acquiredAt;
        public Duration age;
        public Duration ttl;
        public boolean isStale;

        @Override
        public String toString() {
            if (!exists) {
                return "Lock: NOT_HELD";
            }
            return String.format("Lock: HELD, Age: %s min, TTL: %s sec, Stale: %s",
                    age != null ? age.toMinutes() : "unknown",
                    ttl != null ? ttl.toSeconds() : "unknown",
                    isStale);
        }
    }
}