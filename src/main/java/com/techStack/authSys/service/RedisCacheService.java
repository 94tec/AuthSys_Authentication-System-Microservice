package com.techStack.authSys.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.techStack.authSys.models.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
public class RedisCacheService {
    private static final Logger logger = LoggerFactory.getLogger(RedisCacheService.class);

    // Key prefixes
    private static final String USER_PROFILE_PREFIX = "user:profile:";
    private static final String USER_ROLES_PREFIX = "user:roles:";
    private static final String USER_PERMS_PREFIX = "user:permissions:";
    private static final String USER_EXISTS_PREFIX = "userExists:";
    private static final String TOKEN_CLAIMS_PREFIX = "token:claims:";

    // TTL values
    private static final Duration DEFAULT_CACHE_TTL = Duration.ofMinutes(60);
    private static final Duration USER_EXISTS_TTL = Duration.ofHours(24);
    private static final Duration TOKEN_TTL = Duration.ofMinutes(60);

    private final RedisTemplate<String, String> blockingRedisTemplate;
    private final ReactiveRedisTemplate<String, Object> reactiveRedisTemplate;
    private final ObjectMapper objectMapper;

    public RedisCacheService(RedisTemplate<String, String> blockingRedisTemplate,
                             ReactiveRedisTemplate<String, Object> reactiveRedisTemplate,
                             ObjectMapper objectMapper) {
        this.blockingRedisTemplate = blockingRedisTemplate;
        this.reactiveRedisTemplate = reactiveRedisTemplate;
        this.objectMapper = objectMapper;
    }

    // ========== Email Registration Checks ==========
    public Mono<Boolean> isEmailRegistered(String email) {
        if (!StringUtils.hasText(email)) {
            return Mono.just(false);
        }

        String key = USER_EXISTS_PREFIX + email;
        return reactiveRedisTemplate.hasKey(key)
                .onErrorResume(e -> {
                    logger.error("Failed to check email registration: {}", email, e);
                    return Mono.just(false);
                });
    }

    public Mono<Boolean> cacheRegisteredEmail(String email) {
        if (!StringUtils.hasText(email)) {
            return Mono.just(false);
        }

        String key = USER_EXISTS_PREFIX + email;
        return reactiveRedisTemplate.opsForValue()
                .set(key, "true", USER_EXISTS_TTL)
                .onErrorResume(e -> {
                    logger.error("Failed to cache email: {}", email, e);
                    return Mono.just(false);
                });
    }

    public Mono<Boolean> invalidateEmailRegistration(String email) {
        if (!StringUtils.hasText(email)) {
            return Mono.just(false);
        }

        String key = USER_EXISTS_PREFIX + email;
        return reactiveRedisTemplate.delete(key)
                .map(count -> count > 0)
                .onErrorResume(e -> {
                    logger.error("Failed to invalidate email: {}", email, e);
                    return Mono.just(false);
                });
    }

    // ========== User Profile Caching ==========
    public Mono<Boolean> cacheUserProfile(User user) {
        if (user == null || !StringUtils.hasText(user.getId())) {
            return Mono.just(false);
        }

        return Mono.fromCallable(() -> {
                    String key = USER_PROFILE_PREFIX + user.getId();
                    String userJson = objectMapper.writeValueAsString(user);
                    blockingRedisTemplate.opsForValue().set(key, userJson, DEFAULT_CACHE_TTL.toMinutes(), TimeUnit.MINUTES);
                    return true;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    logger.error("Failed to cache user profile: {}", user.getId(), e);
                    return Mono.just(false);
                });
    }

    public Mono<User> getCachedUserProfile(String userId) {
        if (!StringUtils.hasText(userId)) {
            return Mono.empty();
        }

        return Mono.fromCallable(() -> {
                    String key = USER_PROFILE_PREFIX + userId;
                    String userJson = blockingRedisTemplate.opsForValue().get(key);
                    return userJson != null ? objectMapper.readValue(userJson, User.class) : null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    logger.error("Failed to get user profile: {}", userId, e);
                    invalidateUserProfile(userId).subscribe();
                    return Mono.empty();
                });
    }
    /**
     * Invalidates both user profile and email registration cache
     * @param userId User ID to invalidate
     * @param email Email to invalidate
     * @return Mono<Boolean> indicating success (true if both invalidations succeeded)
     */
    public Mono<Boolean> invalidateUserProfile(String userId, String email) {
        return Mono.zip(
                        invalidateUserProfile(userId),
                        StringUtils.hasText(email) ?
                                invalidateEmailRegistration(email) :
                                Mono.just(true)
                )
                .map(tuple -> tuple.getT1() && tuple.getT2())
                .doOnSuccess(success -> {
                    if (success) {
                        logger.debug("Invalidated profile and email for user: {}", userId);
                    } else {
                        logger.warn("Partial invalidation for user: {}", userId);
                    }
                })
                .onErrorResume(e -> {
                    logger.error("Error invalidating user data: {}", userId, e);
                    return Mono.just(false);
                });
    }

    /**
     * Invalidates only the user profile cache
     * @param userId User ID to invalidate
     * @return Mono<Boolean> indicating success
     */
    public Mono<Boolean> invalidateUserProfile(String userId) {
        if (!StringUtils.hasText(userId)) {
            return Mono.just(false);
        }

        String key = USER_PROFILE_PREFIX + userId;
        return reactiveRedisTemplate.delete(key)
                .map(count -> count > 0)
                .doOnSuccess(deleted -> {
                    if (deleted) {
                        logger.debug("Invalidated profile for user: {}", userId);
                    } else {
                        logger.debug("No profile found to invalidate for user: {}", userId);
                    }
                })
                .onErrorResume(e -> {
                    logger.error("Error invalidating profile: {}", userId, e);
                    return Mono.just(false);
                });
    }
    // ========== User Roles Caching ==========
    public Mono<Boolean> cacheUserRoles(String userId, Set<Roles> roles) {
        if (!StringUtils.hasText(userId)) {
            logger.warn("Invalid userId provided for roles caching");
            return Mono.just(false);
        }

        return Mono.fromCallable(() -> objectMapper.writeValueAsString(roles))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(rolesJson -> reactiveRedisTemplate.opsForValue()
                        .set(USER_ROLES_PREFIX + userId, rolesJson, DEFAULT_CACHE_TTL)
                        .doOnSuccess(success -> {
                            if (success) {
                                logger.debug("Cached roles for user: {}", userId);
                            }
                        })
                )
                .onErrorResume(e -> {
                    logger.error("Failed to cache roles for user: {}", userId, e);
                    return Mono.just(false);
                });
    }

    public Mono<Set<Roles>> getCachedUserRoles(String userId) {
        if (!StringUtils.hasText(userId)) {
            return Mono.just(Collections.emptySet());
        }

        return reactiveRedisTemplate.opsForValue()
                .get(USER_ROLES_PREFIX + userId)
                .flatMap(rolesJson -> Mono.fromCallable(() ->
                        objectMapper.readValue(
                                (String) rolesJson,
                                new TypeReference<Set<Roles>>() {}
                        )
                ).subscribeOn(Schedulers.boundedElastic()))
                .onErrorResume(e -> {
                    logger.error("Failed to get cached roles for user: {}", userId, e);
                    return invalidateUserRoles(userId).thenReturn(Collections.emptySet());
                });
    }

    public Mono<Boolean> invalidateUserRoles(String userId) {
        return reactiveRedisTemplate.delete(USER_ROLES_PREFIX + userId)
                .map(count -> count > 0)
                .doOnSuccess(deleted ->
                        logger.debug("Roles cache {} for user: {}",
                                deleted ? "invalidated" : "not found", userId)
                )
                .onErrorResume(e -> {
                    logger.error("Failed to invalidate roles for user: {}", userId, e);
                    return Mono.just(false);
                });
    }

    // ========== User Permissions Caching ==========
    public Mono<Boolean> cacheUserPermissions(String userId, Set<Permissions> permissions) {
        if (!StringUtils.hasText(userId)) {
            logger.warn("Invalid userId provided for permissions caching");
            return Mono.just(false);
        }

        return Mono.fromCallable(() -> objectMapper.writeValueAsString(permissions))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(permsJson -> reactiveRedisTemplate.opsForValue()
                        .set(USER_PERMS_PREFIX + userId, permsJson, DEFAULT_CACHE_TTL)
                        .doOnSuccess(success -> {
                            if (success) {
                                logger.debug("Cached permissions for user: {}", userId);
                            }
                        })
                )
                .onErrorResume(e -> {
                    logger.error("Failed to cache permissions for user: {}", userId, e);
                    return Mono.just(false);
                });
    }

    public Mono<Set<Permissions>> getCachedUserPermissions(String userId) {
        if (!StringUtils.hasText(userId)) {
            return Mono.just(Collections.emptySet());
        }

        return reactiveRedisTemplate.opsForValue()
                .get(USER_PERMS_PREFIX + userId)
                .flatMap(permsJson -> Mono.fromCallable(() ->
                        objectMapper.readValue(
                                (String) permsJson,
                                new TypeReference<Set<Permissions>>() {}
                        )
                ).subscribeOn(Schedulers.boundedElastic()))
                .onErrorResume(e -> {
                    logger.error("Failed to get cached permissions for user: {}", userId, e);
                    return invalidateUserPermissions(userId).thenReturn(Collections.emptySet());
                });
    }

    public Mono<Boolean> invalidateUserPermissions(String userId) {
        return reactiveRedisTemplate.delete(USER_PERMS_PREFIX + userId)
                .map(count -> count > 0)
                .doOnSuccess(deleted ->
                        logger.debug("Permissions cache {} for user: {}",
                                deleted ? "invalidated" : "not found", userId)
                )
                .onErrorResume(e -> {
                    logger.error("Failed to invalidate permissions for user: {}", userId, e);
                    return Mono.just(false);
                });
    }
    // ========== Token Claims Caching ==========
    public Mono<Map<String, Object>> getCachedClaims(String token) {
        if (!StringUtils.hasText(token)) {
            return Mono.error(new IllegalArgumentException("Token cannot be empty"));
        }

        String key = TOKEN_CLAIMS_PREFIX + token;
        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(claims -> {
                    if (claims instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> typedClaims = (Map<String, Object>) claims;
                        return Mono.just(typedClaims);
                    }
                    return Mono.empty();
                })
                .onErrorResume(e -> {
                    logger.error("Failed to get cached claims", e);
                    return Mono.empty();
                });
    }

    public Mono<Boolean> cacheClaims(String token, Map<String, Object> claims) {
        if (!StringUtils.hasText(token) || claims == null) {
            return Mono.just(false);
        }

        String key = TOKEN_CLAIMS_PREFIX + token;
        return reactiveRedisTemplate.opsForValue()
                .set(key, claims, TOKEN_TTL)
                .onErrorResume(e -> {
                    logger.error("Failed to cache claims", e);
                    return Mono.just(false);
                });
    }

    public Mono<Boolean> invalidateToken(String token) {
        if (!StringUtils.hasText(token)) {
            return Mono.just(false);
        }

        String key = TOKEN_CLAIMS_PREFIX + token;
        return reactiveRedisTemplate.delete(key)
                .map(count -> count > 0)
                .onErrorResume(e -> {
                    logger.error("Failed to invalidate token", e);
                    return Mono.just(false);
                });
    }

    // ========== Compound Operations ==========
    public Mono<Boolean> cacheAllUserData(User user, Set<Roles> roles, Set<Permissions> permissions) {
        if (user == null || !StringUtils.hasText(user.getId())) {
            return Mono.just(false);
        }

        return Mono.zip(
                cacheUserProfile(user),
                cacheUserRoles(user.getId(), roles),
                cacheUserPermissions(user.getId(), permissions),
                cacheRegisteredEmail(user.getEmail())
        ).map(tuple -> tuple.getT1() && tuple.getT2() && tuple.getT3() && tuple.getT4());
    }

    public Mono<Boolean> invalidateAllUserData(String userId, String email) {
        return Mono.zip(
                invalidateUserProfile(userId),
                invalidateUserRoles(userId),
                invalidateUserPermissions(userId),
                invalidateEmailRegistration(email)
        ).map(tuple -> tuple.getT1() && tuple.getT2() && tuple.getT3() && tuple.getT4());
    }
}