package com.techStack.authSys.service.security;

import com.google.cloud.firestore.Firestore;
import com.techStack.authSys.exception.security.RateLimitExceededException;
import com.techStack.authSys.models.security.RateLimitRecord;
import com.techStack.authSys.repository.security.BlacklistService;
import com.techStack.authSys.repository.security.RateLimiterService;
import com.techStack.authSys.service.observability.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimiterServiceImpl implements RateLimiterService {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final AuditLogService auditLogService;
    private final BlacklistService blacklistService;

    @Value("${security.rate-limiter.auth.max-per-minute:5}")
    private int maxAttemptsPerMinute;

    @Value("${security.rate-limiter.auth.max-per-hour:20}")
    private int maxAttemptsPerHour;

    @Value("${security.rate-limiter.auth.account-lock-threshold:5}")
    private int accountLockThreshold;

    // Redis key prefixes
    private static final String IP_RATE_KEY_PREFIX = "rate:ip:";
    private static final String EMAIL_RATE_KEY_PREFIX = "rate:email:";
    private static final String OTP_RATE_KEY_PREFIX = "rate:otp:";
    private static final String FAILED_ATTEMPTS_KEY_PREFIX = "failed:";
    private static final String ACCOUNT_LOCK_KEY_PREFIX = "lock:";

    public Mono<Void> checkAuthRateLimit(String ipAddress, String email) {
        return Mono.defer(() -> {
            Instant now = Instant.now();

            return blacklistService.isBlacklisted(ipAddress)
                    .flatMap(blacklisted -> {
                        if (blacklisted) {
                            log.warn("Blacklisted IP attempted auth: {}", ipAddress);
                            return Mono.error(RateLimitExceededException.ipBlacklisted());
                        }
                        return checkAccountLocked(email);
                    })
                    .flatMap(locked -> {
                        if (locked) {
                            return Mono.error(RateLimitExceededException.accountLocked());
                        }

                        // Run both rate limit checks in parallel and wait for both to complete
                        return Mono.when(
                                checkRateLimit(ipAddress, "ip", maxAttemptsPerMinute, maxAttemptsPerHour),
                                checkRateLimit(email, "email", maxAttemptsPerMinute, maxAttemptsPerHour)
                        );
                    });
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Check if account is locked
     */
    private Mono<Boolean> checkAccountLocked(String email) {
        String lockKey = ACCOUNT_LOCK_KEY_PREFIX + email;

        return redisTemplate.hasKey(lockKey)
                .map(locked -> {
                    if (locked) {
                        log.warn("Account locked for email: {}", email);
                    }
                    return locked;
                });
    }

    /**
     * Check rate limit for a specific key (IP or email)
     */
    private Mono<Void> checkRateLimit(String key, String type, int maxPerMinute, int maxPerHour) {
        String minuteKey = getMinuteKey(key, type);
        String hourKey = getHourKey(key, type);

        return Mono.zip(
                getCurrentCount(minuteKey),
                getCurrentCount(hourKey)
        ).flatMap(tuple -> {
            long minuteCount = tuple.getT1();
            long hourCount = tuple.getT2();

            if (minuteCount >= maxPerMinute) {
                log.warn("Minute rate limit exceeded for {}: {}", type, key);
                return Mono.error(new RateLimitExceededException(1,
                        "Too many attempts. Please wait 1 minute."));
            }

            if (hourCount >= maxPerHour) {
                log.warn("Hour rate limit exceeded for {}: {}", type, key);
                return Mono.error(new RateLimitExceededException(60,
                        "Too many attempts. Please try again later."));
            }

            // Increment counters
            return incrementCount(minuteKey, Duration.ofMinutes(1))
                    .then(incrementCount(hourKey, Duration.ofHours(1)))
                    .then();
        });
    }

    /**
     * Get current count for a key
     */
    private Mono<Long> getCurrentCount(String key) {
        return redisTemplate.opsForValue()
                .get(key)
                .map(value -> {
                    try {
                        return Long.parseLong(value);
                    } catch (NumberFormatException e) {
                        return 0L;
                    }
                })
                .defaultIfEmpty(0L);
    }

    /**
     * Increment count for a key
     */
    private Mono<Void> incrementCount(String key, Duration ttl) {
        return redisTemplate.opsForValue()
                .increment(key)
                .flatMap(count -> {
                    if (count == 1) {
                        // First increment, set expiry
                        return redisTemplate.expire(key, ttl);
                    }
                    return Mono.just(true);
                })
                .then();
    }

    /**
     * Get minute rate limit key
     */
    private String getMinuteKey(String key, String type) {
        String minuteSuffix = String.valueOf(Instant.now().getEpochSecond() / 60);
        return IP_RATE_KEY_PREFIX + type + ":" + key + ":minute:" + minuteSuffix;
    }

    /**
     * Get hour rate limit key
     */
    private String getHourKey(String key, String type) {
        String hourSuffix = String.valueOf(Instant.now().getEpochSecond() / 3600);
        return IP_RATE_KEY_PREFIX + type + ":" + key + ":hour:" + hourSuffix;
    }

    @Override
    public Mono<Boolean> recordFailedAttempt(String email, String ipAddress) {
        String failedKey = FAILED_ATTEMPTS_KEY_PREFIX + email;

        return redisTemplate.opsForValue()
                .increment(failedKey)
                .flatMap(count -> {
                    if (count == 1) {
                        // First failed attempt, set expiry to 1 hour
                        return redisTemplate.expire(failedKey, Duration.ofHours(1))
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .flatMap(count -> {
                    boolean shouldLockAccount = count >= accountLockThreshold;

                    if (shouldLockAccount) {
                        log.warn("Account locked for email: {} after {} failed attempts",
                                email, count);

                        // Lock the account for 30 minutes
                        String lockKey = ACCOUNT_LOCK_KEY_PREFIX + email;
                        return redisTemplate.opsForValue()
                                .set(lockKey, "LOCKED", Duration.ofMinutes(30))
                                .thenReturn(true);
                    }

                    // Record failed attempt in audit log
                    return auditLogService.logSecurityEvent(
                            "FAILED_AUTH_ATTEMPT",
                            ipAddress,
                            "Failed attempt " + count + " for email: " + email
                    ).thenReturn(false);
                });
    }

    @Override
    public Mono<Object> checkThreatApiRateLimit(String ipAddress) {
        // Threat API specific rate limiting
        String key = "rate:threat:" + ipAddress + ":" + Instant.now().getEpochSecond() / 60;
        int maxRequests = 10; // 10 requests per minute for threat API

        return redisTemplate.opsForValue()
                .increment(key)
                .flatMap(count -> {
                    if (count == 1) {
                        return redisTemplate.expire(key, Duration.ofMinutes(1))
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .flatMap(count -> {
                    if (count > maxRequests) {
                        return Mono.error(new RateLimitExceededException(1,
                                "Threat API rate limit exceeded"));
                    }
                    return Mono.just(new Object()); // Return empty object for successful check
                });
    }

    @Override
    public Mono<Void> checkOtpRateLimit(String userId, String otpType) {
        String key = OTP_RATE_KEY_PREFIX + otpType.toLowerCase() + ":" + userId;
        int maxRequests = otpType.equalsIgnoreCase("SETUP") ? 5 : 10;  // Setup: 5, Login: 10

        return redisTemplate.opsForValue()
                .get(key)
                .flatMap(value -> {
                    try {
                        long count = Long.parseLong(value);
                        if (count >= maxRequests) {
                            log.warn("OTP rate limit exceeded for user: {} (type: {}, count: {})",
                                    userId, otpType, count);
                            return Mono.error(new RateLimitExceededException(15,
                                    "Too many OTP requests. Please wait 15 minutes."));
                        }
                        return incrementOtpCount(key);
                    } catch (NumberFormatException e) {
                        return incrementOtpCount(key);
                    }
                })
                .switchIfEmpty(incrementOtpCount(key))
                .then();
    }

    /**
     * Increment OTP request count
     */
    private Mono<Void> incrementOtpCount(String key) {
        return redisTemplate.opsForValue()
                .increment(key)
                .flatMap(count -> {
                    if (count == 1) {
                        // Set expiry to 15 minutes
                        return redisTemplate.expire(key, Duration.ofMinutes(15));
                    }
                    return Mono.just(true);
                })
                .then();
    }

    /**
     * Reset failed attempts for successful login
     */
    public Mono<Void> resetFailedAttempts(String email) {
        String failedKey = FAILED_ATTEMPTS_KEY_PREFIX + email;
        String lockKey = ACCOUNT_LOCK_KEY_PREFIX + email;

        return redisTemplate.delete(failedKey)
                .then(redisTemplate.delete(lockKey))
                .then();
    }

    /**
     * Get remaining attempts for a user
     */
    public Mono<Integer> getRemainingAttempts(String email) {
        String failedKey = FAILED_ATTEMPTS_KEY_PREFIX + email;

        return redisTemplate.opsForValue()
                .get(failedKey)
                .map(value -> {
                    try {
                        long count = Long.parseLong(value);
                        return Math.max(0, accountLockThreshold - (int) count);
                    } catch (NumberFormatException e) {
                        return accountLockThreshold;
                    }
                })
                .defaultIfEmpty(accountLockThreshold);
    }

    /**
     * Check if OTP is rate limited
     */
    public Mono<Boolean> isOtpRateLimited(String userId, String otpType) {
        String key = OTP_RATE_KEY_PREFIX + otpType.toLowerCase() + ":" + userId;
        int maxRequests = otpType.equalsIgnoreCase("SETUP") ? 5 : 10;

        return redisTemplate.opsForValue()
                .get(key)
                .map(value -> {
                    try {
                        long count = Long.parseLong(value);
                        return count >= maxRequests;
                    } catch (NumberFormatException e) {
                        return false;
                    }
                })
                .defaultIfEmpty(false);
    }

    /**
     * Get TTL for rate limit in seconds
     */
    public Mono<Long> getRateLimitTtl(String key) {
        return redisTemplate.getExpire(key)
                .map(duration -> duration.getSeconds());
    }
}