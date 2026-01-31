package com.techStack.authSys.service.security;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.Firestore;
import com.techStack.authSys.repository.sucurity.AccountLockService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Account Lock Service Implementation
 *
 * Manages account locking with Redis caching and Firestore persistence.
 * Uses Clock for all timestamp operations.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AccountLockServiceImpl implements AccountLockService {

    private static final String LOCK_PREFIX = "account_lock:";
    private static final String ATTEMPTS_PREFIX = "failed_attempts:";
    private static final String COLLECTION_ACCOUNT_LOCKS = "account_locks";

    /* =========================
       Configuration
       ========================= */

    @Value("${security.account.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.account.lock-duration-minutes:15}")
    private int lockDurationMinutes;

    @Value("${security.account.attempts-window-minutes:30}")
    private int attemptsWindowMinutes;

    /* =========================
       Dependencies
       ========================= */

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final Clock clock;

    /* =========================
       In-Memory Cache
       ========================= */

    private final Map<String, AccountLockInfo> lockCache = new ConcurrentHashMap<>();

    /* =========================
       Lock Status Checks
       ========================= */

    @Override
    public boolean isAccountLocked(String userId) {
        Instant now = clock.instant();

        // Check cache first
        AccountLockInfo lockInfo = lockCache.get(userId);
        if (lockInfo != null) {
            boolean isLocked = lockInfo.unlockTime.isAfter(now);
            if (!isLocked) {
                lockCache.remove(userId);
            }
            return isLocked;
        }

        // Check Redis
        String redisKey = LOCK_PREFIX + userId;
        return Boolean.TRUE.equals(
                redisTemplate.hasKey(redisKey).block()
        );
    }

    @Override
    public Mono<Boolean> isAccountLockedReactive(String userId) {
        Instant now = clock.instant();

        return Mono.fromCallable(() -> {
            // Check cache first
            AccountLockInfo lockInfo = lockCache.get(userId);
            if (lockInfo != null) {
                boolean isLocked = lockInfo.unlockTime.isAfter(now);
                if (!isLocked) {
                    lockCache.remove(userId);
                }
                return isLocked;
            }
            return false;
        }).flatMap(cachedResult -> {
            if (cachedResult) {
                return Mono.just(true);
            }

            // Check Redis
            String redisKey = LOCK_PREFIX + userId;
            return redisTemplate.hasKey(redisKey);
        });
    }

    /* =========================
       Lock Management
       ========================= */

    @Override
    public Mono<Void> lockAccount(String userId, String reason, Duration lockDuration) {
        Instant now = clock.instant();
        Instant unlockTime = now.plus(lockDuration);

        return lockAccountUntil(userId, reason, unlockTime);
    }

    @Override
    public Mono<Void> lockAccountUntil(String userId, String reason, Instant unlockTime) {
        Instant now = clock.instant();
        Duration lockDuration = Duration.between(now, unlockTime);

        log.warn("Locking account {} until {} (reason: {})", userId, unlockTime, reason);

        // Cache in memory
        lockCache.put(userId, new AccountLockInfo(userId, unlockTime, lockDuration, reason, now));

        // Store in Redis
        String redisKey = LOCK_PREFIX + userId;

        return redisTemplate.opsForValue()
                .set(redisKey, unlockTime.toString(), lockDuration)
                .then(persistLockToFirestore(userId, reason, unlockTime, lockDuration, now))
                .doOnSuccess(v -> {
                    log.info("Account {} locked until {} at {}", userId, unlockTime, now);

                    auditLogService.logSecurityEvent(
                            "ACCOUNT_LOCKED",
                            userId,
                            String.format("Account locked until %s. Reason: %s", unlockTime, reason)
                    );
                })
                .doOnError(e -> log.error("Failed to lock account {} at {}: {}",
                        userId, now, e.getMessage()))
                .then();
    }

    @Override
    public void unlockAccount(String userId) {
        Instant now = clock.instant();

        log.info("Unlocking account {} at {}", userId, now);

        // Remove from cache
        lockCache.remove(userId);

        // Remove from Redis
        String redisKey = LOCK_PREFIX + userId;
        redisTemplate.delete(redisKey)
                .doOnSuccess(v -> {
                    log.info("Account {} unlocked at {}", userId, now);

                    auditLogService.logSecurityEvent(
                            "ACCOUNT_UNLOCKED",
                            userId,
                            "Account manually unlocked at " + now
                    );
                })
                .subscribe();

        // Update Firestore
        updateLockStatusInFirestore(userId, false, now)
                .subscribe();
    }

    @Override
    public Mono<Void> unlockAccountReactive(String userId) {
        Instant now = clock.instant();

        log.info("Unlocking account {} at {}", userId, now);

        // Remove from cache
        lockCache.remove(userId);

        // Remove from Redis
        String redisKey = LOCK_PREFIX + userId;

        return redisTemplate.delete(redisKey)
                .then(updateLockStatusInFirestore(userId, false, now))
                .doOnSuccess(v -> {
                    log.info("Account {} unlocked at {}", userId, now);

                    auditLogService.logSecurityEvent(
                            "ACCOUNT_UNLOCKED",
                            userId,
                            "Account manually unlocked at " + now
                    );
                })
                .then();
    }

    /* =========================
       Lock Duration & Timing
       ========================= */

    @Override
    public Duration getRemainingLockTime(String userId) {
        Instant now = clock.instant();

        AccountLockInfo lockInfo = lockCache.get(userId);
        if (lockInfo != null) {
            Duration remaining = Duration.between(now, lockInfo.unlockTime);
            return remaining.isNegative() ? Duration.ZERO : remaining;
        }

        return Duration.ZERO;
    }

    @Override
    public Optional<Duration> getLockDuration(String userId) {
        AccountLockInfo lockInfo = lockCache.get(userId);
        return Optional.ofNullable(lockInfo).map(info -> info.lockDuration);
    }

    @Override
    public Optional<Instant> getUnlockTime(String userId) {
        AccountLockInfo lockInfo = lockCache.get(userId);
        return Optional.ofNullable(lockInfo).map(info -> info.unlockTime);
    }

    @Override
    public Optional<Instant> getLockTime(String userId) {
        AccountLockInfo lockInfo = lockCache.get(userId);
        return Optional.ofNullable(lockInfo).map(info -> info.lockTime);
    }

    /* =========================
       Failed Attempts
       ========================= */

    @Override
    public void recordFailedAttempt(String userId, String ipAddress) {
        Instant now = clock.instant();

        String attemptsKey = ATTEMPTS_PREFIX + userId;

        redisTemplate.opsForValue()
                .increment(attemptsKey)
                .flatMap(count -> {
                    log.warn("Failed login attempt {} for user {} from IP {} at {}",
                            count, userId, ipAddress, now);

                    // Set expiry on first attempt
                    if (count == 1) {
                        return redisTemplate.expire(
                                attemptsKey,
                                Duration.ofMinutes(attemptsWindowMinutes)
                        ).thenReturn(count);
                    }

                    return Mono.just(count);
                })
                .flatMap(count -> {
                    if (count >= maxFailedAttempts) {
                        log.warn("Max failed attempts ({}) reached for user {} at {}",
                                count, userId, now);

                        return lockAccount(
                                userId,
                                String.format("Max failed login attempts (%d) exceeded", count),
                                Duration.ofMinutes(lockDurationMinutes)
                        );
                    }

                    return Mono.empty();
                })
                .doOnSuccess(v ->
                        auditLogService.logSecurityEvent(
                                "FAILED_LOGIN_ATTEMPT",
                                userId,
                                String.format("Failed login from IP %s at %s", ipAddress, now)
                        ))
                .subscribe();
    }

    @Override
    public Mono<Void> recordFailedAttemptReactive(String userId, String ipAddress) {
        Instant now = clock.instant();
        String attemptsKey = ATTEMPTS_PREFIX + userId;

        return redisTemplate.opsForValue()
                .increment(attemptsKey)
                .flatMap(count -> {
                    log.warn("Failed login attempt {} for user {} from IP {} at {}",
                            count, userId, ipAddress, now);

                    // Set expiry on first attempt
                    if (count == 1) {
                        return redisTemplate.expire(
                                attemptsKey,
                                Duration.ofMinutes(attemptsWindowMinutes)
                        ).thenReturn(count);
                    }

                    return Mono.just(count);
                })
                .flatMap(count -> {
                    if (count >= maxFailedAttempts) {
                        log.warn("Max failed attempts ({}) reached for user {} at {}",
                                count, userId, now);

                        return lockAccount(
                                userId,
                                String.format("Max failed login attempts (%d) exceeded", count),
                                Duration.ofMinutes(lockDurationMinutes)
                        );
                    }

                    return Mono.empty();
                })
                .doOnSuccess(v ->
                        auditLogService.logSecurityEvent(
                                "FAILED_LOGIN_ATTEMPT",
                                userId,
                                String.format("Failed login from IP %s at %s", ipAddress, now)
                        ))
                .then();
    }

    @Override
    public int getFailedAttemptCount(String userId) {
        String attemptsKey = ATTEMPTS_PREFIX + userId;

        String countStr = redisTemplate.opsForValue()
                .get(attemptsKey)
                .block();

        return countStr != null ? Integer.parseInt(countStr) : 0;
    }

    @Override
    public void resetFailedAttempts(String userId) {
        Instant now = clock.instant();

        String attemptsKey = ATTEMPTS_PREFIX + userId;
        redisTemplate.delete(attemptsKey)
                .doOnSuccess(v -> log.debug("Reset failed attempts for user {} at {}",
                        userId, now))
                .subscribe();
    }

    @Override
    public Mono<Void> resetFailedAttemptsReactive(String userId) {
        Instant now = clock.instant();
        String attemptsKey = ATTEMPTS_PREFIX + userId;

        return redisTemplate.delete(attemptsKey)
                .doOnSuccess(v -> log.debug("Reset failed attempts for user {} at {}",
                        userId, now))
                .then();
    }

    /* =========================
       Lock Reason & Metadata
       ========================= */

    @Override
    public Optional<String> getLockReason(String userId) {
        AccountLockInfo lockInfo = lockCache.get(userId);
        return Optional.ofNullable(lockInfo).map(info -> info.reason);
    }

    @Override
    public Optional<String> getLastFailedAttemptIp(String userId) {
        // This would require storing IP in Redis/Firestore
        // Implementation depends on your data model
        return Optional.empty();
    }

    @Override
    public Optional<Instant> getLastFailedAttemptTime(String userId) {
        // This would require storing timestamp in Redis/Firestore
        // Implementation depends on your data model
        return Optional.empty();
    }

    /* =========================
       Cleanup Operations
       ========================= */

    @Scheduled(cron = "0 */5 * * * *") // Every 5 minutes
    @Override
    public Mono<Void> cleanupExpiredLocks() {
        Instant now = clock.instant();

        log.debug("Running expired locks cleanup at {}", now);

        return Mono.fromRunnable(() -> {
            lockCache.entrySet().removeIf(entry -> {
                boolean isExpired = entry.getValue().unlockTime.isBefore(now);
                if (isExpired) {
                    log.debug("Removing expired lock for user {} at {}",
                            entry.getKey(), now);
                }
                return isExpired;
            });

            log.info("Expired locks cleanup completed at {}. Active locks: {}",
                    now, lockCache.size());
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    @Override
    public Mono<Void> removeLockData(String userId) {
        Instant now = clock.instant();

        log.info("Removing all lock data for user {} at {}", userId, now);

        // Remove from cache
        lockCache.remove(userId);

        // Remove from Redis
        String lockKey = LOCK_PREFIX + userId;
        String attemptsKey = ATTEMPTS_PREFIX + userId;

        return Mono.when(
                redisTemplate.delete(lockKey),
                redisTemplate.delete(attemptsKey)
        ).doOnSuccess(v -> log.info("Removed lock data for user {} at {}", userId, now));
    }

    /* =========================
       Firestore Persistence
       ========================= */

    /**
     * Persist lock to Firestore
     */
    private Mono<Void> persistLockToFirestore(
            String userId,
            String reason,
            Instant unlockTime,
            Duration lockDuration,
            Instant lockTime
    ) {
        DocumentReference docRef = firestore.collection(COLLECTION_ACCOUNT_LOCKS).document(userId);

        Map<String, Object> lockData = new HashMap<>();
        lockData.put("userId", userId);
        lockData.put("reason", reason);
        lockData.put("lockTime", Timestamp.ofTimeSecondsAndNanos(
                lockTime.getEpochSecond(), lockTime.getNano()));
        lockData.put("unlockTime", Timestamp.ofTimeSecondsAndNanos(
                unlockTime.getEpochSecond(), unlockTime.getNano()));
        lockData.put("lockDurationMinutes", lockDuration.toMinutes());
        lockData.put("isLocked", true);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(docRef.set(lockData)))
                .then();
    }

    /**
     * Update lock status in Firestore
     */
    private Mono<Void> updateLockStatusInFirestore(String userId, boolean isLocked, Instant timestamp) {
        DocumentReference docRef = firestore.collection(COLLECTION_ACCOUNT_LOCKS).document(userId);

        Map<String, Object> updates = new HashMap<>();
        updates.put("isLocked", isLocked);
        updates.put("updatedAt", Timestamp.ofTimeSecondsAndNanos(
                timestamp.getEpochSecond(), timestamp.getNano()));

        if (!isLocked) {
            updates.put("unlockedAt", Timestamp.ofTimeSecondsAndNanos(
                    timestamp.getEpochSecond(), timestamp.getNano()));
        }

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(docRef.update(updates)))
                .then();
    }

    /* =========================
       Inner Classes
       ========================= */

    /**
     * Account lock information
     */
    private record AccountLockInfo(
            String userId,
            Instant unlockTime,
            Duration lockDuration,
            String reason,
            Instant lockTime
    ) {}
}