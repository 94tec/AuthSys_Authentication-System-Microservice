package com.techStack.authSys.service.cache;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.constants.SecurityConstants.CacheKey;
import com.techStack.authSys.constants.SecurityConstants.CacheTTL;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Unified cache service for user data and authentication tokens.
 * Handles: user profiles, roles, permissions, email registration, and token claims.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisUserCacheService {

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private final RedisTemplate<String, String> blockingRedisTemplate;
    private final ReactiveRedisTemplate<String, Object> reactiveRedisTemplate;
    private final ObjectMapper objectMapper;

    // -------------------------------------------------------------------------
    // LOCK OPERATIONS
    // -------------------------------------------------------------------------

    /**
     * Acquires a distributed lock with timeout.
     *
     * @param lockKey   lock identifier
     * @param lockValue unique value for this lock holder
     * @param timeout   lock timeout duration
     * @return Mono<Boolean> true if lock acquired
     */
    public Mono<Boolean> acquireLock(String lockKey, String lockValue, Duration timeout) {
        return reactiveRedisTemplate.opsForValue()
                .setIfAbsent(lockKey, lockValue, timeout)
                .doOnSuccess(acquired -> {
                    if (Boolean.TRUE.equals(acquired)) {
                        log.debug("🔒 Acquired lock: {}", lockKey);
                    } else {
                        log.debug("⏳ Lock already held: {}", lockKey);
                    }
                })
                .defaultIfEmpty(false)
                .onErrorResume(e -> {
                    log.error("Failed to acquire lock {}: {}", lockKey, e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Releases a lock safely using Lua script (only if value matches).
     *
     * @param lockKey   lock identifier
     * @param lockValue expected lock value
     * @return Mono<Boolean> true if lock was released
     */
    public Mono<Boolean> releaseLockSafely(String lockKey, String lockValue) {
        String luaScript = """
                if redis.call("get", KEYS[1]) == ARGV[1] then
                    return redis.call("del", KEYS[1])
                else
                    return 0
                end
                """;

        RedisScript<Long> script = RedisScript.of(luaScript, Long.class);

        return reactiveRedisTemplate.execute(
                        script,
                        Collections.singletonList(lockKey),
                        Collections.singletonList(lockValue))
                .next()
                .map(result -> result != null && result > 0)
                .doOnNext(success -> {
                    if (success) {
                        log.debug("🔓 Released lock: {}", lockKey);
                    } else {
                        log.debug("⚠️ Lock mismatch: {}", lockKey);
                    }
                })
                .onErrorResume(e -> {
                    log.error("Failed to release lock {}: {}", lockKey, e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Basic lock release without ownership check.
     */
    public Mono<Void> releaseLock(String lockKey) {
        return reactiveRedisTemplate.delete(lockKey)
                .doOnSuccess(__ -> log.debug("Released lock: {}", lockKey))
                .then();
    }

    // -------------------------------------------------------------------------
    // EMAIL REGISTRATION CACHE
    // -------------------------------------------------------------------------

    /**
     * Checks if an email is already registered in cache.
     */
    public Mono<Boolean> isEmailRegistered(String email) {
        if (!StringUtils.hasText(email)) return Mono.just(false);

        String key = buildEmailKey(email);
        return reactiveRedisTemplate.hasKey(key)
                .doOnNext(exists -> log.trace("Email {} registration status: {}", email, exists))
                .onErrorResume(e -> {
                    log.error("Failed to check email registration: {}", email, e);
                    return Mono.just(false);
                });
    }

    /**
     * Caches a registered email address.
     */
    public Mono<Void> cacheRegisteredEmail(String email) {
        if (!StringUtils.hasText(email)) {
            log.warn("Attempted to cache null or empty email");
            return Mono.empty();
        }

        String key = buildEmailKey(email);
        return reactiveRedisTemplate.opsForValue()
                .set(key, "true", CacheTTL.EMAIL_REGISTRATION)
                .doOnSuccess(__ -> log.debug("Cached registered email: {}", email))
                .onErrorResume(e -> {
                    log.error("❌ Failed to cache registered email: {}", email, e);
                    return Mono.empty();
                })
                .then();
    }

    /**
     * Removes an email from registration cache.
     */
    public Mono<Boolean> removeRegisteredEmail(String email) {
        if (!StringUtils.hasText(email)) return Mono.just(false);

        String key = buildEmailKey(email);
        return reactiveRedisTemplate.delete(key)
                .map(count -> count > 0)
                .doOnSuccess(removed -> {
                    if (removed) log.debug("🗑️ Removed registered email: {}", email);
                })
                .onErrorResume(e -> {
                    log.error("Failed to remove email: {}", email, e);
                    return Mono.just(false);
                });
    }

    // -------------------------------------------------------------------------
    // USER PROFILE CACHE
    // -------------------------------------------------------------------------

    /**
     * Caches user profile data.
     */
    public Mono<Boolean> cacheUserProfile(User user) {
        if (user == null || !StringUtils.hasText(user.getId())) return Mono.just(false);

        return Mono.fromCallable(() -> {
                    String key      = CacheKey.USER_PROFILE + user.getId();
                    String userJson = objectMapper.writeValueAsString(user);
                    blockingRedisTemplate.opsForValue().set(
                            key, userJson,
                            CacheTTL.USER_DATA.toMinutes(), TimeUnit.MINUTES);
                    return true;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(__ -> log.debug("Cached user profile: {}", user.getId()))
                .onErrorResume(e -> {
                    log.error("Failed to cache user profile: {}", user.getId(), e);
                    return Mono.just(false);
                });
    }

    /**
     * Retrieves cached user profile.
     */
    public Mono<User> getUserProfile(String userId) {
        if (!StringUtils.hasText(userId)) return Mono.empty();

        return Mono.fromCallable(() -> {
                    String key      = CacheKey.USER_PROFILE + userId;
                    String userJson = blockingRedisTemplate.opsForValue().get(key);
                    return userJson != null
                            ? objectMapper.readValue(userJson, User.class)
                            : null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnNext(user -> log.trace("Retrieved user profile: {}", userId))
                .onErrorResume(e -> {
                    log.error("Failed to get user profile: {}", userId, e);
                    return invalidateUserProfile(userId).then(Mono.empty());
                });
    }

    /**
     * Invalidates user profile cache.
     */
    public Mono<Boolean> invalidateUserProfile(String userId) {
        if (!StringUtils.hasText(userId)) return Mono.just(false);

        String key = CacheKey.USER_PROFILE + userId;
        return reactiveRedisTemplate.delete(key)
                .map(count -> count > 0)
                .doOnSuccess(deleted -> {
                    if (deleted) log.debug("Invalidated user profile: {}", userId);
                })
                .onErrorResume(e -> {
                    log.error("Failed to invalidate user profile: {}", userId, e);
                    return Mono.just(false);
                });
    }

    /**
     * Invalidates both user profile and email registration.
     */
    public Mono<Boolean> invalidateUserAndEmail(String userId, String email) {
        Mono<Boolean> profileInvalidation = invalidateUserProfile(userId);
        Mono<Boolean> emailInvalidation   = StringUtils.hasText(email)
                ? removeRegisteredEmail(email)
                : Mono.just(true);

        return Mono.zip(profileInvalidation, emailInvalidation)
                .map(tuple -> tuple.getT1() && tuple.getT2())
                .doOnSuccess(success -> {
                    if (success) {
                        log.debug("Invalidated profile and email for user: {}", userId);
                    } else {
                        log.warn("Partial invalidation for user: {}", userId);
                    }
                })
                .onErrorResume(e -> {
                    log.error("Failed to invalidate user data: {}", userId, e);
                    return Mono.just(false);
                });
    }

    // -------------------------------------------------------------------------
    // USER ROLES CACHE
    // -------------------------------------------------------------------------

    /**
     * Caches user roles as a JSON-serialized Set<Roles>.
     *
     * @param userId user ID
     * @param roles  set of Roles enum values
     */
    public Mono<Boolean> cacheUserRoles(String userId, Set<Roles> roles) {
        if (!StringUtils.hasText(userId)) {
            log.warn("Invalid userId provided for roles caching");
            return Mono.just(false);
        }

        return Mono.fromCallable(() -> objectMapper.writeValueAsString(roles))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(rolesJson -> reactiveRedisTemplate.opsForValue()
                        .set(CacheKey.USER_ROLES + userId, rolesJson, CacheTTL.USER_DATA)
                        .doOnSuccess(success -> {
                            if (success) log.debug("Cached roles for user: {}", userId);
                        }))
                .onErrorResume(e -> {
                    log.error("Failed to cache roles: {}", userId, e);
                    return Mono.just(false);
                });
    }

    /**
     * Retrieves cached user roles.
     */
    public Mono<Set<Roles>> getUserRoles(String userId) {
        if (!StringUtils.hasText(userId)) return Mono.just(Collections.emptySet());

        return reactiveRedisTemplate.opsForValue()
                .get(CacheKey.USER_ROLES + userId)
                .flatMap(rolesJson -> Mono.fromCallable(() ->
                        objectMapper.<Set<Roles>>readValue(
                                (String) rolesJson,
                                new TypeReference<Set<Roles>>() {}
                        )).subscribeOn(Schedulers.boundedElastic()))
                .doOnNext(roles -> log.trace("Retrieved roles for user: {}", userId))
                .onErrorResume(e -> {
                    log.error("Failed to get roles: {}", userId, e);
                    return invalidateUserRoles(userId).thenReturn(Collections.emptySet());
                });
    }

    /**
     * Invalidates user roles cache.
     */
    public Mono<Boolean> invalidateUserRoles(String userId) {
        return reactiveRedisTemplate.delete(CacheKey.USER_ROLES + userId)
                .map(count -> count > 0)
                .doOnSuccess(deleted ->
                        log.debug("Roles cache {} for user: {}",
                                deleted ? "invalidated" : "not found", userId))
                .onErrorResume(e -> {
                    log.error("Failed to invalidate roles: {}", userId, e);
                    return Mono.just(false);
                });
    }

    // -------------------------------------------------------------------------
    // USER PERMISSIONS CACHE
    // -------------------------------------------------------------------------

    /**
     * Caches user permissions as a JSON-serialized List<String>.
     *
     * Permissions are stored as full name strings e.g. "portfolio:publish".
     * No enum conversion — strings are the canonical format.
     *
     * @param userId      user ID
     * @param permissions list of permission full name strings
     */
    public Mono<Boolean> cacheUserPermissions(String userId, List<String> permissions) {
        if (!StringUtils.hasText(userId)) {
            log.warn("Invalid userId provided for permissions caching");
            return Mono.just(false);
        }

        return Mono.fromCallable(() -> objectMapper.writeValueAsString(permissions))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(permsJson -> reactiveRedisTemplate.opsForValue()
                        .set(CacheKey.USER_PERMISSIONS + userId, permsJson, CacheTTL.USER_DATA)
                        .doOnSuccess(success -> {
                            if (success) log.debug("Cached permissions for user: {}", userId);
                        }))
                .onErrorResume(e -> {
                    log.error("Failed to cache permissions: {}", userId, e);
                    return Mono.just(false);
                });
    }

    /**
     * Retrieves cached user permissions.
     *
     * Fix from original:
     *   Return type is Mono<List<String>>. The error path returned
     *   Collections.emptySet() which is a Set, not a List — compile error.
     *   Fixed to Collections.emptyList().
     *
     * @param userId user ID
     * @return Mono<List<String>> list of permission full name strings, or empty list
     */
    public Mono<List<String>> getUserPermissions(String userId) {
        if (!StringUtils.hasText(userId)) return Mono.just(Collections.emptyList());

        return reactiveRedisTemplate.opsForValue()
                .get(CacheKey.USER_PERMISSIONS + userId)
                .flatMap(permsJson -> Mono.fromCallable(() ->
                        objectMapper.<List<String>>readValue(
                                (String) permsJson,
                                new TypeReference<List<String>>() {}
                        )).subscribeOn(Schedulers.boundedElastic()))
                .doOnNext(perms -> log.trace("Retrieved permissions for user: {}", userId))
                .onErrorResume(e -> {
                    log.error("Failed to get permissions: {}", userId, e);
                    // Fix: was Collections.emptySet() — wrong type for Mono<List<String>>
                    return invalidateUserPermissions(userId).thenReturn(Collections.emptyList());
                });
    }

    /**
     * Invalidates user permissions cache.
     */
    public Mono<Boolean> invalidateUserPermissions(String userId) {
        return reactiveRedisTemplate.delete(CacheKey.USER_PERMISSIONS + userId)
                .map(count -> count > 0)
                .doOnSuccess(deleted ->
                        log.debug("Permissions cache {} for user: {}",
                                deleted ? "invalidated" : "not found", userId))
                .onErrorResume(e -> {
                    log.error("Failed to invalidate permissions: {}", userId, e);
                    return Mono.just(false);
                });
    }

    /**
     * Caches user roles and permissions together in one zip.
     *
     * Fix from original:
     *   The original called convertToPermissionsSet(user.getAdditionalPermissions())
     *   which did Permissions.valueOf() on each string — the Permissions enum is gone.
     *   Permissions are already List<String>. We pass them directly to
     *   cacheUserPermissions() with no conversion needed.
     *
     * @param user User with roles and additionalPermissions populated
     * @return Mono<Boolean> true if both cached successfully
     */
    public Mono<Boolean> cacheUserWithRolesAndPermissions(User user) {
        if (user == null || !StringUtils.hasText(user.getId())) {
            log.warn("Cannot cache user — null or missing ID");
            return Mono.just(false);
        }

        Set<Roles>   roles       = user.getRoles();
        List<String> permissions = user.getAdditionalPermissions() != null
                ? user.getAdditionalPermissions()
                : Collections.emptyList();

        log.debug("Caching user {} with {} roles and {} permissions",
                user.getId(), roles.size(), permissions.size());

        return Mono.zip(
                        cacheUserRoles(user.getId(), roles),
                        cacheUserPermissions(user.getId(), permissions))
                .map(tuple -> tuple.getT1() && tuple.getT2())
                .doOnSuccess(success -> {
                    if (success) {
                        log.info("✅ Cached roles and permissions for user: {}", user.getId());
                    } else {
                        log.warn("⚠️ Partial cache failure for user: {}", user.getId());
                    }
                })
                .onErrorResume(e -> {
                    log.error("❌ Failed to cache user with roles/permissions: {}", user.getId(), e);
                    return Mono.just(false);
                });
    }

    // -------------------------------------------------------------------------
    // TOKEN CLAIMS CACHE
    // -------------------------------------------------------------------------

    /**
     * Retrieves cached token claims.
     */
    public Mono<Map<String, Object>> getTokenClaims(String token) {
        if (!StringUtils.hasText(token)) {
            return Mono.error(new IllegalArgumentException("Token cannot be empty"));
        }

        String key = CacheKey.TOKEN_CLAIMS + token;
        return reactiveRedisTemplate.opsForValue()
                .get(key)
                .flatMap(claims -> {
                    if (claims instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> typedClaims = (Map<String, Object>) claims;
                        return Mono.just(typedClaims);
                    }
                    return Mono.empty();
                })
                .doOnNext(__ -> log.trace("Retrieved token claims"))
                .onErrorResume(e -> {
                    log.error("Failed to get token claims", e);
                    return Mono.empty();
                });
    }

    /**
     * Caches token claims.
     */
    public Mono<Boolean> cacheTokenClaims(String token, Map<String, Object> claims) {
        if (!StringUtils.hasText(token) || claims == null) return Mono.just(false);

        String key = CacheKey.TOKEN_CLAIMS + token;
        return reactiveRedisTemplate.opsForValue()
                .set(key, claims, CacheTTL.TOKEN_CLAIMS)
                .doOnSuccess(__ -> log.debug("Cached token claims"))
                .onErrorResume(e -> {
                    log.error("Failed to cache token claims", e);
                    return Mono.just(false);
                });
    }

    /**
     * Invalidates (revokes) a token from cache.
     */
    public Mono<Boolean> revokeToken(String token) {
        if (!StringUtils.hasText(token)) return Mono.just(false);

        String key = CacheKey.TOKEN_CLAIMS + token;
        return reactiveRedisTemplate.delete(key)
                .map(count -> count > 0)
                .doOnSuccess(revoked -> {
                    if (revoked) log.debug("Revoked token from cache");
                })
                .onErrorResume(e -> {
                    log.error("Failed to revoke token", e);
                    return Mono.just(false);
                });
    }

    // -------------------------------------------------------------------------
    // BULK OPERATIONS
    // -------------------------------------------------------------------------

    /**
     * Caches all user-related data in one operation.
     *
     * @param user        user profile
     * @param roles       user roles
     * @param permissions list of permission full name strings
     */
    public Mono<Boolean> cacheAllUserData(
            User user, Set<Roles> roles, List<String> permissions) {
        if (user == null || !StringUtils.hasText(user.getId())) return Mono.just(false);

        return Mono.zip(
                        cacheUserProfile(user),
                        cacheUserRoles(user.getId(), roles),
                        cacheUserPermissions(user.getId(), permissions),
                        cacheRegisteredEmail(user.getEmail()).thenReturn(true))
                .map(tuple -> tuple.getT1() && tuple.getT2() && tuple.getT3() && tuple.getT4())
                .doOnSuccess(success -> {
                    if (success) {
                        log.info("Cached all data for user: {}", user.getId());
                    } else {
                        log.warn("Partial cache failure for user: {}", user.getId());
                    }
                });
    }

    /**
     * Invalidates all user-related data.
     */
    public Mono<Boolean> invalidateAllUserData(String userId, String email) {
        return Mono.zip(
                        invalidateUserProfile(userId),
                        invalidateUserRoles(userId),
                        invalidateUserPermissions(userId),
                        removeRegisteredEmail(email))
                .map(tuple -> tuple.getT1() && tuple.getT2() && tuple.getT3() && tuple.getT4())
                .doOnSuccess(success -> {
                    if (success) {
                        log.info("Invalidated all data for user: {}", userId);
                    } else {
                        log.warn("Partial invalidation for user: {}", userId);
                    }
                });
    }

    // -------------------------------------------------------------------------
    // UTILITY
    // -------------------------------------------------------------------------

    /**
     * Checks if a key exists in cache.
     */
    public Mono<Boolean> keyExists(String key) {
        return reactiveRedisTemplate.hasKey(key)
                .map(result -> result != null && result)
                .onErrorReturn(false);
    }

    // -------------------------------------------------------------------------
    // PRIVATE HELPERS
    // -------------------------------------------------------------------------

    private String buildEmailKey(String email) {
        return CacheKey.REGISTERED_EMAIL + email.toLowerCase();
    }
}