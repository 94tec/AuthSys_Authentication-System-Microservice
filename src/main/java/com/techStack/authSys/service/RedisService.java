package com.techStack.authSys.service;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteBatch;
import com.techStack.authSys.event.BlacklistRemovedEvent;
import com.techStack.authSys.exception.RedisOperationException;
import com.techStack.authSys.models.BlacklistEntry;
import com.techStack.authSys.models.DeviceInfo;
import com.techStack.authSys.models.RequestPattern;
import com.techStack.authSys.models.ThreatInfo;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.repository.RateLimiterService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

// CACHE SERVICE - CHECK IP ADDRESS, THREAT ISSUES, BLACKLIST , SYSTEM ASPECTS.
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisService {

    // Constants
    private static final String THREAT_KEY_PREFIX = "threat:";
    private static final String REQ_PATTERN_KEY_PREFIX = "reqpattern:";
    private static final String DEVICE_KEY_PREFIX = "device:";
    private static final String BLACKLIST_KEY_PREFIX = "secure:blacklist:";

    // Class-level constants
    private static final String BLACKLIST_REDIS_PREFIX = "secure:blacklist:";
    private static final String BLACKLIST_FIRESTORE_COLLECTION = "ip_blacklist";
    private final Firestore firestore;
    private final ApplicationEventPublisher eventPublisher;
    private final RedisTemplate<String, Object> redisTemplate;
    private final ReactiveRedisTemplate<String, Object> reactiveRedisTemplate;
    private final AuditLogService auditLogService;
    private final EncryptionService encryptionService;
    private final RateLimiterService.SessionService sessionService;
    private final MetricsService metricsService;


    @Value("${redis.operation.timeout.seconds:5}")
    private long redisOperationTimeout;

    @Value("${redis.key.prefix:auth_sys:}")
    private String keyPrefix;

    @Value("${redis.blacklist.prefix:blacklist:}")
    private String blacklistPrefix;

    @Value("${redis.blacklist.default-ttl-hours:24}")
    private int defaultBlacklistTtlHours;


    // Caches
    private final Map<String, Boolean> blacklistCache = new ConcurrentHashMap<>();
    private final Map<String, ThreatInfo> threatCache = new ConcurrentHashMap<>();

    public boolean getBlacklistStatus(String encryptedIp) {
        // 1. Validate input
        if (!StringUtils.hasText(encryptedIp)) {
            log.error("Empty encrypted IP provided");
            throw new IllegalArgumentException("Encrypted IP cannot be null or empty");
        }
        if (!encryptionService.isValidEncryptedFormat(encryptedIp)) {
            log.warn("Skipping decryption: IP is not in valid encrypted format: {}", encryptedIp);
            throw new IllegalArgumentException("Invalid encrypted IP format");
        }
        String decryptedIp;
        try {
            decryptedIp = encryptionService.decrypt(encryptedIp);
            log.info("Ip Decrypted Successful: {}", decryptedIp);
        } catch (Exception e) {
            log.error("Decryption failed for IP: {}", encryptedIp, e);
            throw new RuntimeException("Decryption failed", e);
        }

        // 2. Create the Redis key (ensure the key format matches)
        String redisKey = "blacklist:encrypted:" + encryptedIp;  // Correct the key format

        try {
            // 3. Check Redis for the key
            Boolean exists = redisTemplate.hasKey(redisKey);

            // 4. Log and return result
            if (Boolean.TRUE.equals(exists)) {
                log.debug("IP found in blacklist: {}", decryptedIp);
                auditLogService.logSecurityEvent(
                        "BLACKLIST_CHECK",
                        redisKey,
                        "IP found in blacklist"
                );
                return true;
            }

            log.trace("IP not found in blacklist: {}", decryptedIp);
            return false;

        } catch (Exception e) {
            // 5. Handle errors
            String errorMsg = "Failed to check blacklist status for IP: " + decryptedIp;
            log.error("{}: {}", errorMsg, e.getMessage());
            auditLogService.logSecurityEvent(
                    "BLACKLIST_CHECK_FAILED",
                    redisKey,
                    errorMsg
            );

            // 6. Throw custom exception
            throw new com.techStack.authSys.exception.RedisOperationException(errorMsg, e);
        }
    }

    public void setBlacklistStatus(String key, boolean status, Integer ttlHours) {
        try {
            String redisKey = blacklistPrefix + key;
            int expiration = ttlHours != null ? ttlHours : defaultBlacklistTtlHours;

            if (status) {
                redisTemplate.opsForValue().set(redisKey, "blocked", expiration, TimeUnit.HOURS);
                log.warn("Added {} to blacklist for {} hours", key, expiration);
                auditLogService.logSecurityEvent(
                        "BLACKLIST_ADDED",
                        key,
                        STR."Added to blacklist for \{expiration} hours"
                );
            } else {
                redisTemplate.delete(redisKey);
                log.info("Removed {} from blacklist", key);
                auditLogService.logSecurityEvent(
                        "BLACKLIST_REMOVED",
                        key,
                        "Removed from blacklist"
                );
            }
        } catch (Exception e) {
            log.error("Failed to set blacklist status for {}: {}", key, e.getMessage());
            auditLogService.logSystemEvent(
                    "BLACKLIST_OPERATION_FAILED",
                    STR."Failed to modify blacklist status for \{key}"
            );
            throw new RedisOperationException("Blacklist operation failed", e);
        }
    }

    /**
     * Checks if a key is blacklisted
     * @param key The identifier to check
     * @return True if blacklisted, false otherwise
     */
    public boolean isBlacklisted(String key) {
        try {
            String redisKey = blacklistPrefix + key;
            Boolean exists = redisTemplate.hasKey(redisKey);
            if (Boolean.TRUE.equals(exists)) {
                log.debug("Found {} in blacklist", key);
                return true;
            }
            return false;
        } catch (Exception e) {
            log.error("Failed to check blacklist status for {}: {}", key, e.getMessage());
            auditLogService.logSystemEvent(
                    "BLACKLIST_CHECK_FAILED",
                    STR."Failed to check blacklist status for \{key}"
            );
            // Fail safely - assume not blacklisted if we can't verify
            return false;
        }
    }

    /**
     * Gets remaining TTL for a blacklisted key
     * @param key The identifier to check
     * @return Remaining time in hours, or null if not blacklisted
     */
    public Long getBlacklistTtl(String key) {
        try {
            String redisKey = blacklistPrefix + key;
            long ttlSeconds = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
            if (ttlSeconds > 0) {
                long ttlHours = ttlSeconds / 3600;
                log.debug("Blacklist TTL for {}: {} hours", key, ttlHours);
                return ttlHours;
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to get blacklist TTL for {}: {}", key, e.getMessage());
            return null;
        }
    }
    /**
     * Removes an encrypted IP from the blacklist across all storage layers
     *
     * @param encryptedIp The encrypted IP address to remove (must be valid Base64)
     * @throws IllegalArgumentException if the encrypted IP is invalid
     * @throws RedisOperationException  if the operation fails
     */
    public Mono<Void> removeBlacklistStatus(String encryptedIp) {
        // 1. Input validation
        if (encryptionService.isValidEncryptedFormat(encryptedIp)) {
            String validationError = "Invalid encrypted IP format";
            log.error("{}: {}", validationError, encryptedIp);
            auditLogService.logSecurityEvent("BLACKLIST_REMOVE_REJECTED", encryptedIp, validationError);
            return Mono.error(new IllegalArgumentException(validationError));
        }

        // 2. Generate consistent keys
        String redisKey = BLACKLIST_REDIS_PREFIX + encryptedIp;
        String firestoreKey = encryptedIp; // Firestore uses raw encrypted IP as ID

        // 3. Remove from Redis (Reactive)
        Mono<Boolean> redisDeleteMono = reactiveRedisTemplate.opsForValue().delete(redisKey)
                .onErrorResume(e -> {
                    log.error("Failed to delete from Redis: {}", e.getMessage());
                    return Mono.just(false);
                });

        // 4. Remove from Firestore
        Mono<Void> firestoreDeleteMono = Mono.fromCallable(() -> {
            WriteBatch batch = firestore.batch();
            batch.delete(firestore.collection(BLACKLIST_FIRESTORE_COLLECTION).document(firestoreKey));
            batch.commit().get(); // Blocking call - must be wrapped in Mono
            return null;
        }).onErrorResume(e -> {
            log.error("Failed to delete from Firestore: {}", e.getMessage());
            return Mono.empty();
        }).then();

        // 5. Execute both removals in parallel and process the result
        return Mono.zip(redisDeleteMono, firestoreDeleteMono)
                .doOnSuccess(result -> {
                    // 6. Clear from local cache
                    blacklistCache.remove(encryptedIp);

                    // 7. Log successful removal
                    log.info("Removed blacklist status for IP (Redis:{}, Firestore:{}): {}",
                            result.getT1(), true, encryptedIp);
                    auditLogService.logSecurityEvent("BLACKLIST_REMOVED", encryptedIp, "Successfully removed from all storage layers");

                    // 8. Publish removal event
                    eventPublisher.publishEvent(new BlacklistRemovedEvent(this, encryptedIp));
                })
                .doOnError(e -> {
                    // 9. Log failure
                    String errorMsg = "Failed to remove blacklist status for IP " + encryptedIp;
                    log.error("{}: {}", errorMsg, e.getMessage());
                    auditLogService.logSecurityEvent("BLACKLIST_REMOVE_FAILURE", encryptedIp, errorMsg);
                })
                .then(Mono.fromRunnable(() -> postRemovalCleanup(encryptedIp))) // 10. Cleanup
                .then();
    }
    // Supporting methods
    private void postRemovalCleanup(String encryptedIp) {
        try {
            // Clean up any related session data
            sessionService.cleanupAfterBlacklistRemoval(encryptedIp);

            // Update monitoring metrics
            metricsService.recordBlacklistRemoval();
        } catch (Exception e) {
            log.warn("Post-removal cleanup failed for {}: {}", encryptedIp, e.getMessage());
        }
    }
    /**
     * Store a value in Redis with a specified expiration time.
     *
     * @param key   The key under which data is stored.
     * @param value The value to store.
     * @throws RedisOperationException if operation fails
     */
    public Mono<Void> setKey(String key, Object value, Duration ttl) {
        validateKey(key);
        validateValue(value);

        String prefixedKey = prefixKey(key);

        return Mono.fromRunnable(() -> {
            try {
                redisTemplate.opsForValue().set(prefixedKey, value, ttl);
                log.info("Stored key {} in Redis for duration {}", prefixedKey, ttl);
                auditLogService.logDataOperation("REDIS_SET", prefixedKey, "Success");
            } catch (Exception e) {
                String errorMsg = String.format("Failed to store key %s in Redis", prefixedKey);
                log.error("{}: {}", errorMsg, e.getMessage());
                auditLogService.logDataOperation("REDIS_SET_FAILURE", prefixedKey, errorMsg);
                throw new RedisOperationException(errorMsg, e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }


    /**
     * Retrieve a value from Redis.
     *
     * @param key The key to fetch.
     * @return The stored object or null if not found.
     * @throws RedisOperationException if operation fails
     */
    public Mono<Object> getKey(String key) {
        validateKey(key);
        String prefixedKey = prefixKey(key);

        return Mono.fromCallable(() -> {
            try {
                Object value = executeWithTimeout(
                        () -> redisTemplate.opsForValue().get(prefixedKey),
                        "GET", prefixedKey
                );
                if (value == null) {
                    log.debug("Key {} not found in Redis", prefixedKey);
                    return Mono.empty();  // Return empty if key is not found
                }
                log.debug("Retrieved key {} from Redis", prefixedKey);
                return Mono.just(value);
            } catch (Exception e) {
                String errorMsg = String.format("Failed to fetch key %s from Redis", prefixedKey);
                log.error("{}: {}", errorMsg, e.getMessage());
                auditLogService.logDataOperation("REDIS_GET_FAILURE", prefixedKey, errorMsg);
                return Mono.error(new RedisOperationException(errorMsg, e));
            }
        }).subscribeOn(Schedulers.boundedElastic()).block();
    }
    /**
     * Remove a key from Redis.
     *
     * @param key The key to delete.
     * @throws RedisOperationException if operation fails
     */
    public Mono<Void> deleteKey(String key) throws RedisOperationException {
        validateKey(key);
        String prefixedKey = prefixKey(key);

        try {
            Boolean result = executeWithTimeout(
                    () -> redisTemplate.delete(prefixedKey),
                    "DELETE", prefixedKey
            );
            if (Boolean.TRUE.equals(result)) {
                log.info("Deleted key {} from Redis", prefixedKey);
                auditLogService.logDataOperation("REDIS_DELETE", prefixedKey, "Success");
            } else {
                log.warn("Key {} not found in Redis for deletion", prefixedKey);
            }
        } catch (Exception e) {
            String errorMsg = String.format("Failed to delete key %s from Redis", prefixedKey);
            log.error("{}: {}", errorMsg, e.getMessage());
            auditLogService.logDataOperation("REDIS_DELETE_FAILURE", prefixedKey, errorMsg);
            throw new RedisOperationException(errorMsg, e);
        }
        return null;
    }

    /**
     * Atomically increment a counter value.
     *
     * @param key The key of the counter.
     * @return The incremented value.
     * @throws RedisOperationException if operation fails
     */
    public Mono<Object> incrementValue(String key, Duration ttl) {
        validateKey(key);
        String prefixedKey = prefixKey(key);

        return Mono.fromCallable(() -> {
            try {
                Long value = executeWithTimeout(
                        () -> redisTemplate.opsForValue().increment(prefixedKey),
                        "INCR", prefixedKey
                );

                if (value != null && value == 1L && ttl != null) {
                    // Only set the TTL if this is the first increment
                    redisTemplate.expire(prefixedKey, ttl);
                    log.debug("Set TTL of {} on key {}", ttl, prefixedKey);
                }

                log.debug("Incremented key {} in Redis to {}", prefixedKey, value);
                return value != null ? value : 0;
            } catch (Exception e) {
                String errorMsg = String.format("Failed to increment key %s in Redis", prefixedKey);
                log.error("{}: {}", errorMsg, e.getMessage());
                return Mono.error(new RedisOperationException(errorMsg, e));
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Set value if key doesn't exist (NX operation).
     *
     * @param key   The key under which data is stored.
     * @param value The value to store.
     * @param hours Expiration time in hours.
     * @return true if set, false if key exists
     * @throws RedisOperationException if operation fails
     */
    public boolean setIfAbsent(String key, Object value, int hours) throws RedisOperationException {
        validateKey(key);
        validateValue(value);
        String prefixedKey = prefixKey(key);

        try {
            Boolean result = executeWithTimeout(
                    () -> redisTemplate.opsForValue().setIfAbsent(prefixedKey, value, hours, TimeUnit.HOURS),
                    "SETNX", prefixedKey
            );
            log.debug("SetIfAbsent operation for key {} returned {}", prefixedKey, result);
            return Boolean.TRUE.equals(result);
        } catch (Exception e) {
            String errorMsg = String.format("Failed to setIfAbsent for key %s in Redis", prefixedKey);
            log.error("{}: {}", errorMsg, e.getMessage());
            throw new RedisOperationException(errorMsg, e);
        }
    }

    private <T> T executeWithTimeout(Supplier<T> operation, String operationType, String key) {
        try {
            return operation.get();
        } catch (SerializationException e) {
            String errorMsg = String.format("Serialization failed for %s operation on key %s", operationType, key);
            log.error("{}: {}", errorMsg, e.getMessage());
            throw new RedisOperationException(errorMsg, e);
        } catch (Exception e) {
            String errorMsg = String.format("Redis operation %s timed out for key %s", operationType, key);
            log.error("{}: {}", errorMsg, e.getMessage());
            throw new RedisOperationException(errorMsg, e);
        }
    }

    private void validateKey(String key) {
        if (!StringUtils.hasText(key)) {
            throw new IllegalArgumentException("Redis key cannot be null or empty");
        }
        if (key.contains(" ") || key.length() > 256) {
            throw new IllegalArgumentException("Invalid Redis key format");
        }
    }

    private void validateValue(Object value) {
        if (value == null) {
            throw new IllegalArgumentException("Redis value cannot be null");
        }
    }

    private String prefixKey(String key) {
        return keyPrefix + key;
    }

    // ================== Threat Detection Methods ================== //

    /**
     * Retrieves comprehensive threat information
     */
    public Mono<ThreatInfo> getThreatInfo(String threatKey) {
        // 1. Check local cache first
        ThreatInfo cachedInfo = threatCache.get(threatKey);
        if (cachedInfo != null) {
            return Mono.just(cachedInfo);
        }

        // 2. Check Redis
        return reactiveRedisTemplate.opsForValue().get(THREAT_KEY_PREFIX + threatKey)
                .flatMap(obj -> {
                    if (obj instanceof ThreatInfo) {
                        ThreatInfo info = (ThreatInfo) obj;
                        threatCache.put(threatKey, info); // Update local cache
                        return Mono.just(info);
                    }
                    return Mono.empty();
                })
                .switchIfEmpty(Mono.just(new ThreatInfo(threatKey))) // Return empty threat info if not found
                .timeout(Duration.ofSeconds(redisOperationTimeout))
                .onErrorResume(e -> {
                    log.error("Threat info lookup failed for {}: {}", threatKey, e.getMessage());
                    metricsService.incrementCounter("threat.lookup.failure");
                    return Mono.just(new ThreatInfo(threatKey)); // Fail-safe default
                });
    }
    public Mono<Boolean> cacheThreatInfo(String cacheKey, Boolean result, long cacheTtlSeconds) {
        return reactiveRedisTemplate.opsForValue()
                .set("threat:" + cacheKey, result, Duration.ofSeconds(cacheTtlSeconds))
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        log.debug("Threat info cached for key: {}", cacheKey);
                    }
                })
                .doOnError(e -> log.error("Error caching threat info for {}: {}", cacheKey, e.getMessage()));
    }


    /**
     * Caches threat information with TTL
     */
    public Mono<Boolean> cacheThreatInfo(ThreatInfo threatInfo, long ttlSeconds) {
        String key = THREAT_KEY_PREFIX + threatInfo.getThreatKey();

        return reactiveRedisTemplate.opsForValue()
                .set(key, threatInfo, Duration.ofSeconds(ttlSeconds))
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        threatCache.put(threatInfo.getThreatKey(), threatInfo);
                        metricsService.incrementCounter("threat.cache.success");
                        log.debug("Cached threat info for {}", threatInfo.getThreatKey());
                    }
                })
                .onErrorResume(e -> {
                    log.error("Failed to cache threat info: {}", e.getMessage());
                    metricsService.incrementCounter("threat.cache.failure");
                    return Mono.just(false);
                });
    }

    /**
     * Checks if a request pattern is suspicious
     */
    public Mono<Boolean> isSuspiciousRequestPattern(String userId, String endpoint) {
        String key = REQ_PATTERN_KEY_PREFIX + userId + ":" + endpoint;

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(obj -> {
                    if (obj instanceof RequestPattern) {
                        RequestPattern pattern = (RequestPattern) obj;
                        boolean suspicious = pattern.getRequestCount() > pattern.getNormalThreshold();
                        return Mono.just(suspicious);
                    }
                    return Mono.just(false);
                })
                .defaultIfEmpty(false)
                .timeout(Duration.ofSeconds(2))
                .onErrorResume(e -> {
                    log.warn("Request pattern check failed: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    // ================== Request Pattern Tracking ================== //

    /**
     * Records a request pattern for anomaly detection
     */
    public Mono<Void> recordRequestPattern(String userId, String endpoint) {
        String key = REQ_PATTERN_KEY_PREFIX + userId + ":" + endpoint;

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(obj -> {
                    RequestPattern pattern = (obj instanceof RequestPattern)
                            ? (RequestPattern) obj
                            : new RequestPattern(userId, endpoint, 1, 0, Instant.now());

                    pattern.incrementCount();
                    return reactiveRedisTemplate.opsForValue()
                            .set(key, pattern, Duration.ofHours(1));
                })
                .then()
                .doOnError(e -> log.error("Failed to record request pattern: {}", e.getMessage()));
    }

    // ================== Device Management ================== //

    /**
     * Stores device information with enhanced security
     */
    public Mono<Boolean> storeDeviceInfo(DeviceInfo deviceInfo) {
        String key = DEVICE_KEY_PREFIX + deviceInfo.getUserId() + ":" + deviceInfo.getDeviceFingerprint();

        return reactiveRedisTemplate.opsForValue()
                .set(key, deviceInfo, Duration.ofDays(30))
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        auditLogService.logDeviceEvent("DEVICE_REGISTERED", deviceInfo);
                    }
                })
                .onErrorResume(e -> {
                    log.error("Device info storage failed: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Retrieves device information with validation
     */
    public Mono<DeviceInfo> getDeviceInfo(String userId, String deviceFingerprint) {
        String key = DEVICE_KEY_PREFIX + userId + ":" + deviceFingerprint;

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(obj -> {
                    if (obj instanceof DeviceInfo) {
                        DeviceInfo device = (DeviceInfo) obj;
                        return Mono.just(device);
                    }
                    return Mono.empty();
                })
                .timeout(Duration.ofSeconds(2))
                .onErrorResume(e -> {
                    log.warn("Device lookup failed: {}", e.getMessage());
                    return Mono.empty();
                });
    }

    public Mono<RequestPattern> getUserRequestPattern(String userId, String endpoint) {
        String key = String.format("reqpattern:%s:%s", userId, endpoint);

        return reactiveRedisTemplate.opsForValue()
                .get(key)
                .flatMap(result -> {
                    if (result instanceof RequestPattern) {
                        return Mono.just((RequestPattern) result);
                    }
                    return Mono.empty(); // If invalid format, return empty
                })
                .switchIfEmpty(Mono.just(new RequestPattern(userId, endpoint, 0, 0, Instant.now())))
                .doOnError(e -> log.error("Error retrieving request pattern for {}: {}", key, e.getMessage()));
    }
    public Mono<List<DeviceInfo>> getUserDevices(String userId) {
        // Validate input
        if (!StringUtils.hasText(userId)) {
            return Mono.error(new IllegalArgumentException("User ID cannot be empty"));
        }

        String devicePattern = DEVICE_KEY_PREFIX + userId + ":*";

        return reactiveRedisTemplate.keys(devicePattern)
                .flatMap(key -> reactiveRedisTemplate.opsForValue().get(key))
                .filter(DeviceInfo.class::isInstance)
                .map(DeviceInfo.class::cast)
                .collectList()
                .timeout(Duration.ofSeconds(3))
                .doOnSuccess(devices ->
                        log.debug("Retrieved {} devices for user {}", devices.size(), userId))
                .doOnError(e ->
                        log.error("Failed to get devices for user {}: {}", userId, e.getMessage()))
                .onErrorResume(e -> {
                    metricsService.incrementCounter("device.lookup.failure");
                    return Mono.just(List.of()); // Return empty list on failure
                });
    }
    /**
     * Enhanced version with pagination and filtering
     */
    public Mono<PaginatedDevices> getUserDevicesPaginated(
            String userId,
            int page,
            int size,
            DeviceFilter filter
    ) {
        return getUserDevices(userId)
                .map(devices -> {
                    // Apply filters
                    List<DeviceInfo> filtered = devices.stream()
                            .filter(device -> filter == null || filter.matches(device))
                            .toList();

                    // Apply pagination
                    int total = filtered.size();
                    int fromIndex = Math.min(page * size, total);
                    int toIndex = Math.min((page + 1) * size, total);

                    return new PaginatedDevices(
                            filtered.subList(fromIndex, toIndex),
                            page,
                            size,
                            total
                    );
                });
    }
    /**
     * Revokes all devices except the current one
     */
    public Mono<Void> revokeOtherDevices(String userId, String currentDeviceFingerprint) {
        return getUserDevices(userId)
                .flatMap(devices -> Flux.fromIterable(devices)
                        .filter(device -> !device.getDeviceFingerprint().equals(currentDeviceFingerprint))
                        .flatMap(device -> reactiveRedisTemplate.delete(
                                DEVICE_KEY_PREFIX + userId + ":" + device.getDeviceFingerprint()
                        ))
                        .then())
                .doOnSuccess(__ ->
                        log.info("Revoked all other devices for user {}", userId))
                .doOnError(e ->
                        log.error("Failed to revoke devices for user {}: {}", userId, e.getMessage()));
    }

    /**
     * Gets device count per user
     */
    public Mono<Long> getUserDeviceCount(String userId) {
        String pattern = DEVICE_KEY_PREFIX + userId + ":*";

        return reactiveRedisTemplate.keys(pattern)
                .count()
                .timeout(Duration.ofSeconds(2))
                .defaultIfEmpty(0L);
    }

    /**
     * Updates device information
     */
    public Mono<Boolean> updateDeviceInfo(DeviceInfo deviceInfo) {
        String key = STR."\{DEVICE_KEY_PREFIX}\{deviceInfo.getUserId()}:\{deviceInfo.getDeviceFingerprint()}";

        return reactiveRedisTemplate.opsForValue()
                .set(key, deviceInfo)
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        log.debug("Updated device {}", deviceInfo.getDeviceFingerprint());
                        auditLogService.logDeviceEvent("DEVICE_UPDATED", deviceInfo);
                    }
                });
    }
    /**
     * Removes device information from Redis
     * @param userId The user ID owning the device
     * @param deviceFingerprint The unique device fingerprint
     * @return Mono<Boolean> true if device was found and removed, false otherwise
     */
    public Mono<Boolean> removeDeviceInfo(String userId, String deviceFingerprint) {
        // Validate inputs
        if (!StringUtils.hasText(userId)){
            return Mono.error(new IllegalArgumentException("User ID cannot be empty"));
        }
        if (!StringUtils.hasText(deviceFingerprint)) {
            return Mono.error(new IllegalArgumentException("Device fingerprint cannot be empty"));
        }

        String key = String.format("device:%s:%s", userId, deviceFingerprint);

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(device -> {
                    if (device instanceof DeviceInfo) {
                        // Device exists, proceed with deletion
                        return reactiveRedisTemplate.delete(key)
                                .doOnSuccess(deleted -> {
                                    if (deleted > 0) {
                                        log.info("Removed device {} for user {}", deviceFingerprint, userId);
                                        auditLogService.logSecurityEvent(
                                                "DEVICE_REMOVED",
                                                userId,
                                                Map.of(
                                                        "deviceFingerprint", deviceFingerprint,
                                                        "action", "manual_removal"
                                                ).toString()
                                        );
                                        metricsService.incrementCounter("device.removed");
                                    }
                                });
                    }
                    return Mono.just(false);
                })
                .defaultIfEmpty(false)
                .timeout(Duration.ofSeconds(3))
                .onErrorResume(e -> {
                    log.error("Failed to remove device {} for user {}: {}",
                            deviceFingerprint, userId, e.getMessage());
                    metricsService.incrementCounter("device.removal.failed");
                    return Mono.just(false);
                }).hasElement();
    }

    /**
     * Enhanced version that returns the removed device info
     */
    public Mono<DeviceInfo> removeAndReturnDeviceInfo(String userId, String deviceFingerprint) {
        String key = String.format("device:%s:%s", userId, deviceFingerprint);

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(device -> {
                    if (device instanceof DeviceInfo) {
                        DeviceInfo deviceInfo = (DeviceInfo) device;
                        return reactiveRedisTemplate.delete(key)
                                .flatMap(deleted -> deleted > 0
                                        ? Mono.just(deviceInfo)
                                        : Mono.empty());
                    }
                    return Mono.empty();
                })
                .timeout(Duration.ofSeconds(3))
                .doOnSuccess(device ->
                        log.info("Removed and returned device {}", deviceFingerprint))
                .doOnError(e ->
                        log.error("Device removal failed: {}", e.getMessage()));
    }

    /**
     * Removes all devices for a user except the specified one
     */
    public Mono<Integer> removeAllDevicesExcept(String userId, String deviceFingerprintToKeep) {
        return getUserDevices(userId)
                .flatMapMany(Flux::fromIterable)
                .filter(device -> !device.getDeviceFingerprint().equals(deviceFingerprintToKeep))
                .flatMap(device -> removeDeviceInfo(userId, device.getDeviceFingerprint()))
                .filter(Boolean::booleanValue)
                .collectList()
                .map(List::size)
                .doOnSuccess(count ->
                        log.info("Removed {} devices for user {}", count, userId))
                .doOnError(e ->
                        log.error("Bulk device removal failed: {}", e.getMessage()))
                .defaultIfEmpty(0);
    }

    /**
     * Removes devices older than specified days
     */
    public Mono<Integer> removeInactiveDevices(String userId, int daysInactive) {
        Instant cutoff = Instant.now().minus(daysInactive, ChronoUnit.DAYS);

        return getUserDevices(userId)
                .flatMapMany(Flux::fromIterable)
                .filter(device -> device.getLastActive().isBefore(cutoff))
                .flatMap(device -> removeDeviceInfo(userId, device.getDeviceFingerprint()))
                .filter(Boolean::booleanValue)
                .collectList()
                .map(List::size)
                .doOnSuccess(count ->
                        log.info("Removed {} inactive devices for user {}", count, userId))
                .doOnError(e ->
                        log.error("Inactive device cleanup failed: {}", e.getMessage()));
    }
    // ================== Blacklist Management ================== //

    public Mono<Boolean> addToBlacklist(String key, String reason, int ttlHours) {
        String redisKey = BLACKLIST_KEY_PREFIX + key;
        BlacklistEntry entry = new BlacklistEntry(key, reason, Instant.now(), encryptionService);

        return reactiveRedisTemplate.opsForValue()
                .set(redisKey, entry, Duration.ofHours(ttlHours))
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        blacklistCache.put(key, true);
                        auditLogService.logSecurityEvent("BLACKLIST_ADDED", key, reason);
                    }
                })
                .onErrorResume(e -> {
                    log.error("Blacklist operation failed: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    // ================== Utility Methods ================== //

    private <T> Mono<T> executeWithTimeout(Mono<T> operation, String operationName) {
        return operation.timeout(Duration.ofSeconds(redisOperationTimeout))
                .onErrorResume(e -> {
                    log.error("Redis {} timed out: {}", operationName, e.getMessage());
                    metricsService.incrementCounter("redis.timeout." + operationName.toLowerCase());
                    return Mono.empty();
                });
    }

    private String buildKey(String... components) {
        return keyPrefix + String.join(":", components);
    }
    @Data
    public static class PaginatedDevices {
        private final List<DeviceInfo> devices;
        private final int currentPage;
        private final int pageSize;
        private final int totalCount;
    }
    @FunctionalInterface
    public interface DeviceFilter {
        boolean matches(DeviceInfo device);

        // Common filter examples
        static DeviceFilter activeDevices() {
            return device -> device.getLastActive().isAfter(Instant.now().minus(30, ChronoUnit.DAYS));
        }

        static DeviceFilter suspiciousDevices() {
            return device -> device.getTrustLevel() == DeviceInfo.DeviceTrustLevel.SUSPICIOUS;
        }
    }

}

