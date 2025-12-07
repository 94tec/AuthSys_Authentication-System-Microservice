package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.exception.EmailAlreadyExistsException;
import com.techStack.authSys.service.FirebaseServiceAuth;
import com.techStack.authSys.service.RedisCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Handles duplicate email detection using a two-tier strategy:
 * 1. Redis cache (fast, eventual consistency)
 * 2. Firebase Auth (source of truth)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DuplicateEmailCheckService {

    private final RedisCacheService redisCacheService;
    private final FirebaseServiceAuth firebaseServiceAuth;

    /**
     * Checks if an email is already registered.
     * Uses Redis first for speed, then Firebase Auth as fallback.
     */
    public Mono<UserDTO> checkDuplicateEmail(UserDTO userDto) {
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
     * Check Redis cache for email existence.
     * Failures are non-fatal - falls back to Firebase check.
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
     * Check Firebase Auth for email existence (source of truth).
     */
    private Mono<Boolean> checkFirebaseAuth(String email) {
        return firebaseServiceAuth.checkEmailAvailability(email)
                .onErrorResume(e -> {
                    log.error("❌ Firebase Auth lookup failed for {}: {}", email, e.getMessage());
                    // In production, consider throwing a 503 here if Firebase is down
                    // For now, assume email doesn't exist if we can't check
                    return Mono.just(false);
                });
    }

    /**
     * Backfills Redis cache if email exists in Firebase but not in cache.
     * This is a fire-and-forget operation to improve future lookup performance.
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
