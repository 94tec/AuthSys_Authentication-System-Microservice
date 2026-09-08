package com.techStack.authSys.identity.service;

import com.techStack.authSys.auth.exception.EmailAlreadyExistsException;
import com.techStack.authSys.auth.service.FirebaseServiceAuth;
import com.techStack.authSys.common.cache.RedisUserCacheService;
import com.techStack.authSys.common.util.HelperUtils;
import com.techStack.authSys.identity.dto.UserRegistrationDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Duplicate Email Check Service
 *
 * Two-tier email uniqueness validation with Clock-based tracking:
 * 1. Redis cache (fast, eventual consistency)
 * 2. Firebase Auth (source of truth)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DuplicateEmailCheckService {

    private final RedisUserCacheService redisCacheService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final Clock clock;

    /**
     * Check if email is already registered.
     * Errors with EmailAlreadyExistsException if taken — designed for
     * self-registration flows that want a fail-fast Mono chain.
     */
    public Mono<UserRegistrationDTO> checkDuplicateEmail(UserRegistrationDTO userDto) {
        Instant checkStart = clock.instant();
        String email = userDto.getEmail();

        Mono<Boolean> redisCheck = checkRedisCache(email);
        Mono<Boolean> firebaseCheck = checkFirebaseAuth(email);

        return Mono.zip(redisCheck, firebaseCheck)
                .flatMap(tuple -> {
                    boolean inRedis = tuple.getT1();
                    boolean inFirebase = tuple.getT2();

                    Instant checkEnd = clock.instant();
                    Duration duration = Duration.between(checkStart, checkEnd);

                    log.debug("Duplicate check at {} in {} for {} → Redis: {}, Firebase: {}",
                            checkEnd, duration, HelperUtils.maskEmail(email),
                            inRedis, inFirebase);

                    if (inRedis || inFirebase) {
                        backfillCacheIfNeeded(email, inRedis, inFirebase);
                        return Mono.error(new EmailAlreadyExistsException(email));
                    }

                    return Mono.just(userDto);
                })
                .doOnSuccess(dto -> {
                    Instant successTime = clock.instant();
                    Duration duration = Duration.between(checkStart, successTime);
                    log.debug("✅ Email available at {} in {}: {}",
                            successTime, duration, HelperUtils.maskEmail(email));
                });
    }

    /**
     * Lightweight availability check — no UserRegistrationDTO required, no error
     * thrown on a taken email. Returns true if available, false if already
     * registered (Redis cache or Firebase Auth).
     *
     * Intended for flows like staff/admin creation that just need a boolean to
     * branch on (e.g. AdminEmailGate), rather than a fail-fast exception chain.
     * Reuses the same two-tier Redis + Firebase lookup as checkDuplicateEmail,
     * so both flows share one source of truth for "is this email taken".
     */
    public Mono<Boolean> checkEmailAvailability(String email) {
        Instant checkStart = clock.instant();

        Mono<Boolean> redisCheck = checkRedisCache(email);
        Mono<Boolean> firebaseCheck = checkFirebaseAuth(email);

        return Mono.zip(redisCheck, firebaseCheck)
                .map(tuple -> {
                    boolean inRedis = tuple.getT1();
                    boolean inFirebase = tuple.getT2();

                    Instant checkEnd = clock.instant();
                    Duration duration = Duration.between(checkStart, checkEnd);

                    log.debug("Availability check at {} in {} for {} → Redis: {}, Firebase: {}",
                            checkEnd, duration, HelperUtils.maskEmail(email),
                            inRedis, inFirebase);

                    boolean taken = inRedis || inFirebase;
                    if (taken) {
                        backfillCacheIfNeeded(email, inRedis, inFirebase);
                    }
                    return !taken;
                });
    }

    /**
     * Check Redis cache (non-fatal failures)
     */
    private Mono<Boolean> checkRedisCache(String email) {
        return redisCacheService.isEmailRegistered(email)
                .onErrorResume(e -> {
                    log.warn("Redis lookup failed for {} at {}: {} - using Firebase fallback",
                            HelperUtils.maskEmail(email), clock.instant(), e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Check Firebase Auth (source of truth)
     */
    private Mono<Boolean> checkFirebaseAuth(String email) {
        return firebaseServiceAuth.checkEmailAvailability(email)
                .onErrorResume(e -> {
                    log.error("❌ Firebase Auth lookup failed at {} for {}: {}",
                            clock.instant(), HelperUtils.maskEmail(email), e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Backfill Redis cache if email exists in Firebase but not cache
     */
    private void backfillCacheIfNeeded(String email, boolean inRedis, boolean inFirebase) {
        if (inFirebase && !inRedis) {
            redisCacheService.cacheRegisteredEmail(email)
                    .subscribeOn(Schedulers.boundedElastic())
                    .doOnSuccess(v -> log.debug("Backfilled cache at {} for {}",
                            clock.instant(), HelperUtils.maskEmail(email)))
                    .doOnError(e -> log.warn("Failed to backfill cache at {} for {}: {}",
                            clock.instant(), HelperUtils.maskEmail(email), e.getMessage()))
                    .subscribe(); // Fire and forget
        }
    }
}