package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.service.cache.RedisUserCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Bootstrap Lock Service
 *
 * Manages distributed locking for bootstrap operations.
 * Uses Clock for timestamp tracking and stale lock detection.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapLockService {

    /* =========================
       Dependencies
       ========================= */

    private final RedisTemplate<String, Object> redisTemplate;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    private static final String LOCK_KEY = "bootstrap:lock";
    private static final String LOCK_TIMESTAMP_KEY = "bootstrap:lock:timestamp";
    private static final Duration LOCK_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration STALE_LOCK_THRESHOLD = Duration.ofMinutes(10);

    /* =========================
       Lock Acquisition
       ========================= */

    /**
     * Attempt to acquire the bootstrap lock with stale lock detection
     */
    public Mono<Boolean> acquireBootstrapLock() {
        Instant now = clock.instant();

        log.debug("Attempting to acquire bootstrap lock at {}", now);

        return checkAndClearStaleLock()
                .flatMap(staleCleared -> {
                    if (staleCleared) {
                        log.warn("🧹 Cleared stale bootstrap lock at {}", clock.instant());
                    }
                    return attemptLockAcquisition();
                })
                .onErrorResume(e -> {
                    log.warn("⚠️ Failed to acquire bootstrap lock at {}: {}",
                            clock.instant(), e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Check for and clear stale locks
     */
    private Mono<Boolean> checkAndClearStaleLock() {
        return Mono.fromCallable(() -> {
            Instant now = clock.instant();

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
                    log.warn("⚠️ Found lock without timestamp at {} - clearing as stale", now);
                    redisTemplate.delete(LOCK_KEY);
                    redisTemplate.delete(LOCK_TIMESTAMP_KEY);
                    return true;
                }

                // Check if lock is stale
                Instant lockTime = Instant.ofEpochMilli(timestamp);
                Duration lockAge = Duration.between(lockTime, now);

                if (lockAge.compareTo(STALE_LOCK_THRESHOLD) > 0) {
                    log.warn("⚠️ Found stale lock (age: {} minutes) at {} - clearing",
                            lockAge.toMinutes(), now);
                    redisTemplate.delete(LOCK_KEY);
                    redisTemplate.delete(LOCK_TIMESTAMP_KEY);
                    return true;
                }

                return false; // Lock is fresh

            } catch (Exception e) {
                log.error("Error checking for stale lock at {}: {}", now, e.getMessage());
                return false;
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Attempt to acquire the lock
     */
    private Mono<Boolean> attemptLockAcquisition() {
        Instant now = clock.instant();
        String lockValue = generateLockValue(now);
        long timestamp = now.toEpochMilli();

        return Mono.fromCallable(() -> {
            // Try to acquire lock
            Boolean acquired = redisTemplate.opsForValue()
                    .setIfAbsent(LOCK_KEY, lockValue,
                            LOCK_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);

            if (Boolean.TRUE.equals(acquired)) {
                // Set timestamp for stale lock detection
                redisTemplate.opsForValue().set(
                        LOCK_TIMESTAMP_KEY,
                        timestamp,
                        LOCK_TIMEOUT.toMillis(),
                        TimeUnit.MILLISECONDS
                );

                log.info("🔒 Bootstrap lock acquired at {} (timeout: {})", now, LOCK_TIMEOUT);
                return true;
            }

            log.info("⏳ Bootstrap lock already held at {}", now);
            return false;

        }).subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       Lock Release
       ========================= */

    /**
     * Release the bootstrap lock
     */
    public void releaseBootstrapLock() {
        Instant now = clock.instant();

        try {
            redisTemplate.delete(LOCK_KEY);
            redisTemplate.delete(LOCK_TIMESTAMP_KEY);
            log.info("🔓 Bootstrap lock released at {}", now);
        } catch (Exception e) {
            log.warn("⚠️ Failed to release bootstrap lock at {}: {}", now, e.getMessage());
        }
    }

    /**
     * Force release of the bootstrap lock (for manual intervention)
     * USE WITH CAUTION - only call if certain no instance is running bootstrap
     */
    public Mono<Void> forceReleaseLock() {
        Instant now = clock.instant();

        return Mono.fromRunnable(() -> {
            try {
                Boolean lockExisted = redisTemplate.hasKey(LOCK_KEY);
                Boolean timestampExisted = redisTemplate.hasKey(LOCK_TIMESTAMP_KEY);

                redisTemplate.delete(LOCK_KEY);
                redisTemplate.delete(LOCK_TIMESTAMP_KEY);

                if (Boolean.TRUE.equals(lockExisted)) {
                    log.warn("⚠️ FORCED release of bootstrap lock at {}", now);
                }
                if (Boolean.TRUE.equals(timestampExisted)) {
                    log.warn("⚠️ FORCED removal of lock timestamp at {}", now);
                }
            } catch (Exception e) {
                log.error("Failed to force release lock at {}: {}", now, e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /* =========================
       Lock Status
       ========================= */

    /**
     * Get lock status information for debugging
     */
    public Mono<LockStatus> getLockStatus() {
        return Mono.fromCallable(() -> {
            Instant now = clock.instant();
            LockStatus status = new LockStatus();

            try {
                status.exists = Boolean.TRUE.equals(redisTemplate.hasKey(LOCK_KEY));
                status.checkedAt = now;

                if (status.exists) {
                    Long timestamp = (Long) redisTemplate.opsForValue().get(LOCK_TIMESTAMP_KEY);
                    if (timestamp != null) {
                        status.acquiredAt = Instant.ofEpochMilli(timestamp);
                        status.age = Duration.between(status.acquiredAt, now);
                        status.isStale = status.age.compareTo(STALE_LOCK_THRESHOLD) > 0;
                    }

                    // Get TTL
                    Long ttl = redisTemplate.getExpire(LOCK_KEY, TimeUnit.SECONDS);
                    if (ttl != null && ttl > 0) {
                        status.ttl = Duration.ofSeconds(ttl);
                    }
                }
            } catch (Exception e) {
                log.error("Error getting lock status at {}: {}", now, e.getMessage());
            }

            return status;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Generate a unique lock value for this instance
     */
    private String generateLockValue(Instant timestamp) {
        return String.format("%s-%d-%s",
                Thread.currentThread().getName(),
                timestamp.toEpochMilli(),
                UUID.randomUUID().toString().substring(0, 8)
        );
    }

    /* =========================
       Inner Classes
       ========================= */

    /**
     * Lock status information
     */
    public static class LockStatus {
        public boolean exists;
        public Instant checkedAt;
        public Instant acquiredAt;
        public Duration age;
        public Duration ttl;
        public boolean isStale;

        @Override
        public String toString() {
            if (!exists) {
                return String.format("Lock: NOT_HELD (checked at: %s)", checkedAt);
            }
            return String.format("Lock: HELD, Age: %s min, TTL: %s sec, Stale: %s, Checked at: %s",
                    age != null ? age.toMinutes() : "unknown",
                    ttl != null ? ttl.toSeconds() : "unknown",
                    isStale,
                    checkedAt);
        }
    }
}