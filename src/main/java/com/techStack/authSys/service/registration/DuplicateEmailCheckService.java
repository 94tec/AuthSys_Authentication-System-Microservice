package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.email.EmailAlreadyExistsException;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Duplicate Email Check Service
 *
 * Two-tier email uniqueness validation:
 * 1. Redis cache (fast, eventual consistency)
 * 2. Firebase Auth (source of truth)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DuplicateEmailCheckService {

    private final RedisUserCacheService redisCacheService;
    private final FirebaseServiceAuth firebaseServiceAuth;

    /**
     * Check if email is already registered
     */
    public Mono<UserRegistrationDTO> checkDuplicateEmail(UserRegistrationDTO userDto) {
        String email = userDto.getEmail();

        Mono<Boolean> redisCheck = checkRedisCache(email);
        Mono<Boolean> firebaseCheck = checkFirebaseAuth(email);

        return Mono.zip(redisCheck, firebaseCheck)
                .flatMap(tuple -> {
                    boolean inRedis = tuple.getT1();
                    boolean inFirebase = tuple.getT2();

                    log.debug("Duplicate check for {} → Redis: {}, Firebase: {}",
                            email, inRedis, inFirebase);

                    if (inRedis || inFirebase) {
                        backfillCacheIfNeeded(email, inRedis, inFirebase);
                        return Mono.error(new EmailAlreadyExistsException(email));
                    }

                    return Mono.just(userDto);
                })
                .doOnSuccess(dto -> log.debug("✅ Email {} is available", email));
    }

    /**
     * Check Redis cache (non-fatal failures)
     */
    private Mono<Boolean> checkRedisCache(String email) {
        return redisCacheService.isEmailRegistered(email)
                .onErrorResume(e -> {
                    log.warn("Redis lookup failed for {}: {} - using Firebase fallback",
                            email, e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Check Firebase Auth (source of truth)
     */
    private Mono<Boolean> checkFirebaseAuth(String email) {
        return firebaseServiceAuth.checkEmailAvailability(email)
                .onErrorResume(e -> {
                    log.error("❌ Firebase Auth lookup failed for {}: {}",
                            email, e.getMessage());
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
                    .doOnSuccess(v -> log.debug("Backfilled cache for {}", email))
                    .doOnError(e -> log.warn("Failed to backfill cache for {}: {}",
                            email, e.getMessage()))
                    .subscribe(); // Fire and forget
        }
    }
}