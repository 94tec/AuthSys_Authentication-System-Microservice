package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.email.EmailAlreadyExistsException;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.util.validation.HelperUtils;
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
     * Check if email is already registered
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
