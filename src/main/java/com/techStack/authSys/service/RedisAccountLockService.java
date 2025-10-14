package com.techStack.authSys.service;

import com.techStack.authSys.models.AccountLockInfo;
import com.techStack.authSys.repository.AccountLockService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisAccountLockService implements AccountLockService {

    private static final String LOCK_KEY_PREFIX = "account:lock:";
    private static final String FAILED_ATTEMPTS_KEY_PREFIX = "account:failed:";
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration DEFAULT_LOCK_DURATION = Duration.ofMinutes(30);
    private static final long FAILED_ATTEMPT_EXPIRY_HOURS = 1;

    private final RedisTemplate<String, Object> redisTemplate;
    private final AuditLogService auditLogService;

    @Override
    public boolean isAccountLocked(String userId) {
        String key = LOCK_KEY_PREFIX + userId;
        boolean locked = Boolean.TRUE.equals(redisTemplate.hasKey(key));
        log.debug("Account lock status for user {}: {}", userId, locked);
        return locked;
    }

    @Override
    public Mono<Void> lockAccount(String userId, String reason, Duration lockDuration) {
        String key = LOCK_KEY_PREFIX + userId;
        Duration duration = (lockDuration != null) ? lockDuration : DEFAULT_LOCK_DURATION;

        redisTemplate.opsForValue().set(
                key,
                new AccountLockInfo(reason, Instant.now()),
                duration.toMillis(),
                TimeUnit.MILLISECONDS
        );

        log.info("Account locked: user={}, reason={}, duration={}", userId, reason, duration);
        auditLogService.logSecurityEvent(
                "ACCOUNT_LOCKED",
                userId,
                Map.of(
                        "reason", reason,
                        "duration", duration.toString(),
                        "lockedAt", Instant.now().toString()
                ).toString()
        );
        return null;
    }

    @Override
    public void unlockAccount(String userId) {
        String key = LOCK_KEY_PREFIX + userId;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(key))) {
            redisTemplate.delete(key);
            log.info("Account unlocked: user={}", userId);
            auditLogService.logSecurityEvent("ACCOUNT_UNLOCKED", userId, "Manual unlock");
        } else {
            log.warn("Unlock attempt on a non-locked account: user={}", userId);
        }
    }

    @Override
    public Duration getRemainingLockTime(String userId) {
        String key = LOCK_KEY_PREFIX + userId;
        Long expire = redisTemplate.getExpire(key, TimeUnit.MILLISECONDS);
        Duration remainingTime = (expire != null && expire > 0) ? Duration.ofMillis(expire) : Duration.ZERO;

        log.debug("Remaining lock time for user {}: {}", userId, remainingTime);
        return remainingTime;
    }

    @Override
    public void recordFailedAttempt(String userId, String ipAddress) {
        String key = FAILED_ATTEMPTS_KEY_PREFIX + userId;

        // Increment failed attempts count
        Long attempts = redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, FAILED_ATTEMPT_EXPIRY_HOURS, TimeUnit.HOURS); // Reset counter after 1 hour

        log.warn("Failed login attempt: user={}, ip={}, attempt={}", userId, ipAddress, attempts);

        // Log the failed attempt
        auditLogService.logSecurityEvent(
                "LOGIN_FAILURE",
                userId,
                Map.of(
                        "attempt", (attempts != null ? attempts : 1),
                        "ip", ipAddress,
                        "timestamp", Instant.now().toString()
                ).toString()
        );

        // Auto-lock if max attempts reached
        if (attempts != null && attempts >= MAX_FAILED_ATTEMPTS) {
            log.error("Account locked due to excessive failed attempts: user={}", userId);
            lockAccount(userId, "Too many failed attempts", DEFAULT_LOCK_DURATION);
            redisTemplate.delete(key);
        }
    }

}

