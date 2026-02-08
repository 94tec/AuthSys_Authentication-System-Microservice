package com.techStack.authSys.service.firebase;

import com.google.firebase.auth.FirebaseToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Firebase Token Cache Service
 *
 * Caches Firebase authentication tokens in Redis to reduce Firebase API calls.
 * Uses Clock for timestamp tracking and TTL management.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FirebaseTokenCacheService {

    /* =========================
       Constants
       ========================= */

    private static final String CACHE_KEY_PREFIX = "firebase-token:";
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(30);

    /* =========================
       Dependencies
       ========================= */

    private final ReactiveRedisTemplate<String, FirebaseToken> redisTemplate;
    private final Clock clock;

    /* =========================
       Cache Operations
       ========================= */

    /**
     * Get cached Firebase token
     */
    public Mono<FirebaseToken> getCachedToken(String token) {
        Instant retrievalStart = clock.instant();
        String cacheKey = cacheKey(token);

        log.debug("Retrieving cached Firebase token at {} - Key: {}",
                retrievalStart, maskKey(cacheKey));

        return redisTemplate.opsForValue()
                .get(cacheKey)
                .doOnSuccess(cachedToken -> {
                    Instant retrievalEnd = clock.instant();
                    Duration duration = Duration.between(retrievalStart, retrievalEnd);

                    if (cachedToken != null) {
                        log.info("✅ Firebase token cache HIT at {} in {} - UID: {}",
                                retrievalEnd, duration, cachedToken.getUid());
                    } else {
                        log.debug("Firebase token cache MISS at {} in {}",
                                retrievalEnd, duration);
                    }
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to retrieve cached Firebase token at {}: {}",
                            errorTime, e.getMessage());
                });
    }

    /**
     * Cache Firebase token with default TTL
     */
    public Mono<Boolean> cacheToken(String token, FirebaseToken firebaseToken) {
        return cacheToken(token, firebaseToken, DEFAULT_TTL);
    }

    /**
     * Cache Firebase token with custom TTL
     */
    public Mono<Boolean> cacheToken(
            String token,
            FirebaseToken firebaseToken,
            Duration ttl) {

        Instant cacheStart = clock.instant();
        String cacheKey = cacheKey(token);

        log.debug("Caching Firebase token at {} - UID: {}, TTL: {}",
                cacheStart, firebaseToken.getUid(), ttl);

        return redisTemplate.opsForValue()
                .set(cacheKey, firebaseToken, ttl)
                .doOnSuccess(success -> {
                    Instant cacheEnd = clock.instant();
                    Duration duration = Duration.between(cacheStart, cacheEnd);

                    if (Boolean.TRUE.equals(success)) {
                        log.info("✅ Firebase token cached at {} in {} - UID: {}, Expires: {}",
                                cacheEnd,
                                duration,
                                firebaseToken.getUid(),
                                cacheEnd.plus(ttl));
                    } else {
                        log.warn("⚠️ Failed to cache Firebase token at {} - UID: {}",
                                cacheEnd, firebaseToken.getUid());
                    }
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Error caching Firebase token at {} for UID {}: {}",
                            errorTime, firebaseToken.getUid(), e.getMessage());
                })
                .onErrorReturn(false);
    }

    /**
     * Invalidate cached token
     */
    public Mono<Boolean> invalidateToken(String token) {
        Instant invalidationStart = clock.instant();
        String cacheKey = cacheKey(token);

        log.info("Invalidating Firebase token at {} - Key: {}",
                invalidationStart, maskKey(cacheKey));

        return redisTemplate.opsForValue()
                .delete(cacheKey)
                .doOnSuccess(deleted -> {
                    Instant invalidationEnd = clock.instant();
                    Duration duration = Duration.between(invalidationStart, invalidationEnd);

                    if (Boolean.TRUE.equals(deleted)) {
                        log.info("✅ Firebase token invalidated at {} in {}",
                                invalidationEnd, duration);
                    } else {
                        log.debug("Token not found in cache at {}", invalidationEnd);
                    }
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to invalidate Firebase token at {}: {}",
                            errorTime, e.getMessage());
                })
                .onErrorReturn(false);
    }

    /**
     * Invalidate all Firebase tokens for a user
     */
    public Mono<Long> invalidateUserTokens(String userId) {
        Instant invalidationStart = clock.instant();
        String pattern = CACHE_KEY_PREFIX + "*";

        log.info("Invalidating all Firebase tokens at {} for user: {}",
                invalidationStart, userId);

        return redisTemplate.keys(pattern)
                .flatMap(key -> redisTemplate.opsForValue().get(key)
                        .filter(token -> userId.equals(token.getUid()))
                        .flatMap(token -> redisTemplate.delete(key))
                )
                .count()
                .doOnSuccess(count -> {
                    Instant invalidationEnd = clock.instant();
                    Duration duration = Duration.between(invalidationStart, invalidationEnd);

                    log.info("✅ Invalidated {} Firebase token(s) at {} in {} for user: {}",
                            count, invalidationEnd, duration, userId);
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to invalidate user tokens at {} for user {}: {}",
                            errorTime, userId, e.getMessage());
                })
                .onErrorReturn(0L);
    }

    /**
     * Check if token exists in cache
     */
    public Mono<Boolean> hasToken(String token) {
        Instant checkStart = clock.instant();
        String cacheKey = cacheKey(token);

        return redisTemplate.hasKey(cacheKey)
                .doOnSuccess(exists -> {
                    Instant checkEnd = clock.instant();
                    Duration duration = Duration.between(checkStart, checkEnd);

                    log.debug("Token existence check at {} in {}: {}",
                            checkEnd, duration, exists);
                })
                .onErrorReturn(false);
    }

    public Mono<Duration> getTokenTTL(String token) {
        String cacheKey = cacheKey(token);

        return redisTemplate.getExpire(cacheKey)
                .map(ttl -> {
                    if (ttl == null || ttl.isNegative()) {
                        return Duration.ZERO;
                    }
                    return ttl;
                })
                .defaultIfEmpty(Duration.ZERO)
                .onErrorReturn(Duration.ZERO);
    }

    /**
     * Refresh token TTL
     */
    public Mono<Boolean> refreshTokenTTL(String token) {
        return refreshTokenTTL(token, DEFAULT_TTL);
    }

    /**
     * Refresh token TTL with custom duration
     */
    public Mono<Boolean> refreshTokenTTL(String token, Duration ttl) {
        Instant refreshStart = clock.instant();
        String cacheKey = cacheKey(token);

        log.debug("Refreshing token TTL at {} - TTL: {}", refreshStart, ttl);

        return redisTemplate.expire(cacheKey, ttl)
                .doOnSuccess(refreshed -> {
                    Instant refreshEnd = clock.instant();
                    Duration duration = Duration.between(refreshStart, refreshEnd);

                    if (Boolean.TRUE.equals(refreshed)) {
                        log.info("✅ Token TTL refreshed at {} in {} - New expiry: {}",
                                refreshEnd, duration, refreshEnd.plus(ttl));
                    } else {
                        log.warn("⚠️ Failed to refresh token TTL at {}", refreshEnd);
                    }
                })
                .onErrorReturn(false);
    }

    /**
     * Get cache statistics
     */
    public Mono<CacheStats> getCacheStats() {
        Instant statsStart = clock.instant();
        String pattern = CACHE_KEY_PREFIX + "*";

        return redisTemplate.keys(pattern)
                .count()
                .map(count -> {
                    Instant statsEnd = clock.instant();
                    Duration duration = Duration.between(statsStart, statsEnd);

                    CacheStats stats = new CacheStats(
                            count,
                            statsEnd,
                            duration
                    );

                    log.debug("Cache stats retrieved at {} in {}: {} tokens",
                            statsEnd, duration, count);

                    return stats;
                })
                .onErrorReturn(new CacheStats(0L, clock.instant(), Duration.ZERO));
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Generate cache key from token
     */
    private String cacheKey(String token) {
        String hashedToken = DigestUtils.sha256Hex(token);
        return CACHE_KEY_PREFIX + hashedToken;
    }

    /**
     * Mask cache key for logging
     */
    private String maskKey(String key) {
        if (key == null || key.length() <= 20) {
            return key;
        }
        return key.substring(0, 20) + "...";
    }

    /* =========================
       Inner Classes
       ========================= */

    /**
     * Cache statistics
     */
    public record CacheStats(
            Long cachedTokenCount,
            Instant retrievedAt,
            Duration retrievalDuration
    ) {
        @Override
        public String toString() {
            return String.format(
                    "CacheStats{count=%d, retrievedAt=%s, duration=%s}",
                    cachedTokenCount,
                    retrievedAt,
                    retrievalDuration
            );
        }
    }
}