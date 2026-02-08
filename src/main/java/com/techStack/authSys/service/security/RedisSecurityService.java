package com.techStack.authSys.service.security;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteBatch;
import com.techStack.authSys.event.BlacklistRemovedEvent;
import com.techStack.authSys.exception.data.RedisOperationException;
import com.techStack.authSys.models.security.BlacklistEntry;
import com.techStack.authSys.models.session.DeviceInfo;
import com.techStack.authSys.models.security.RequestPattern;
import com.techStack.authSys.models.security.ThreatInfo;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.service.observability.AuditLogService;
import io.jsonwebtoken.io.SerializationException;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Unified Redis service for security operations including:
 * - IP blacklisting and threat detection
 * - Device management and tracking
 * - Request pattern analysis
 * - General key-value operations
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisSecurityService {

    // ==================== Key Prefixes ====================
    private static final class KeyPrefix {
        static final String THREAT = "threat:";
        static final String REQUEST_PATTERN = "reqpattern:";
        static final String DEVICE = "device:";
        static final String BLACKLIST = "secure:blacklist:";
        static final String BLACKLIST_ENCRYPTED = "blacklist:encrypted:";
    }

    // ==================== Collections ====================
    private static final String FIRESTORE_BLACKLIST_COLLECTION = "ip_blacklist";

    // ==================== Dependencies ====================
    private final Firestore firestore;
    private final ApplicationEventPublisher eventPublisher;
    private final RedisTemplate<String, Object> redisTemplate;
    private final ReactiveRedisTemplate<String, Object> reactiveRedisTemplate;
    private final AuditLogService auditLogService;
    private final EncryptionService encryptionService;
    private final SessionService sessionService;
    private final MetricsService metricsService;
    private final Clock clock;

    // ==================== Configuration ====================
    @Value("${redis.operation.timeout.seconds:5}")
    private long operationTimeoutSeconds;

    @Value("${redis.key.prefix:auth_sys:}")
    private String keyPrefix;

    @Value("${redis.blacklist.prefix:blacklist:}")
    private String blacklistPrefix;

    @Value("${redis.blacklist.default-ttl-hours:24}")
    private int defaultBlacklistTtlHours;

    // ==================== Local Caches ====================
    private final Map<String, Boolean> blacklistCache = new ConcurrentHashMap<>();
    private final Map<String, ThreatInfo> threatInfoCache = new ConcurrentHashMap<>();

    // ==================== BLACKLIST OPERATIONS ====================

    /**
     * Checks if an encrypted IP is blacklisted
     * @param encryptedIp Base64 encrypted IP address
     * @return true if blacklisted, false otherwise
     * @throws IllegalArgumentException if IP format is invalid
     * @throws RedisOperationException if Redis operation fails
     */
    public boolean isIpBlacklisted(String encryptedIp) {
        encryptionService.validateEncryptedIp(encryptedIp);

        String decryptedIp = encryptionService.decrypt(encryptedIp);
        String redisKey = KeyPrefix.BLACKLIST_ENCRYPTED + encryptedIp;

        try {
            Boolean exists = redisTemplate.hasKey(redisKey);

            if (Boolean.TRUE.equals(exists)) {
                log.debug("IP found in blacklist: {}", decryptedIp);
                auditLogService.logSecurityEvent("BLACKLIST_CHECK", redisKey, "IP found in blacklist");
                return true;
            }

            log.trace("IP not found in blacklist: {}", decryptedIp);
            return false;

        } catch (Exception e) {
            String errorMsg = "Failed to check blacklist status for IP: " + decryptedIp;
            log.error("{}: {}", errorMsg, e.getMessage());
            auditLogService.logSecurityEvent("BLACKLIST_CHECK_FAILED", redisKey, errorMsg);
            throw new RedisOperationException(errorMsg, e);
        }
    }

    /**
     * Adds or removes an entry from the blacklist
     * @param identifier Key to blacklist (IP, user ID, etc.)
     * @param shouldBlacklist true to add, false to remove
     * @param ttlHours Optional TTL in hours (uses default if null)
     */
    public void updateBlacklistStatus(String identifier, boolean shouldBlacklist, Integer ttlHours) {
        try {
            String redisKey = blacklistPrefix + identifier;
            int expirationHours = ttlHours != null ? ttlHours : defaultBlacklistTtlHours;

            if (shouldBlacklist) {
                redisTemplate.opsForValue().set(redisKey, "blocked", expirationHours, TimeUnit.HOURS);
                log.warn("Blacklisted {} for {} hours", identifier, expirationHours);
                auditLogService.logSecurityEvent("BLACKLIST_ADDED", identifier,
                        String.format("Blacklisted for %d hours", expirationHours));
            } else {
                redisTemplate.delete(redisKey);
                log.info("Removed {} from blacklist", identifier);
                auditLogService.logSecurityEvent("BLACKLIST_REMOVED", identifier, "Removed from blacklist");
            }
        } catch (Exception e) {
            log.error("Failed to update blacklist status for {}: {}", identifier, e.getMessage());
            auditLogService.logSystemEvent("BLACKLIST_OPERATION_FAILED",
                    String.format("Failed to modify blacklist status for %s", identifier));
            throw new RedisOperationException("Blacklist operation failed", e);
        }
    }

    /**
     * Checks if any identifier is blacklisted
     * @param identifier The identifier to check
     * @return true if blacklisted, false otherwise (fails safely)
     */
    public boolean isBlacklisted(String identifier) {
        try {
            String redisKey = blacklistPrefix + identifier;
            Boolean exists = redisTemplate.hasKey(redisKey);
            if (Boolean.TRUE.equals(exists)) {
                log.debug("Found {} in blacklist", identifier);
                return true;
            }
            return false;
        } catch (Exception e) {
            log.error("Failed to check blacklist status for {}: {}", identifier, e.getMessage());
            auditLogService.logSystemEvent("BLACKLIST_CHECK_FAILED",
                    String.format("Failed to check blacklist status for %s", identifier));
            return false; // Fail safely
        }
    }

    /**
     * Gets remaining TTL for a blacklisted identifier
     * @param identifier The identifier to check
     * @return Remaining time in hours, or null if not blacklisted
     */
    public Long getBlacklistRemainingHours(String identifier) {
        try {
            String redisKey = blacklistPrefix + identifier;
            long ttlSeconds = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
            if (ttlSeconds > 0) {
                long ttlHours = ttlSeconds / 3600;
                log.debug("Blacklist TTL for {}: {} hours", identifier, ttlHours);
                return ttlHours;
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to get blacklist TTL for {}: {}", identifier, e.getMessage());
            return null;
        }
    }

    /**
     * Removes an encrypted IP from all storage layers (Redis + Firestore)
     * @param encryptedIp The encrypted IP address to remove
     * @return Mono<Void> completing when removal is done
     */
    public Mono<Void> removeIpFromBlacklist(String encryptedIp) {
        if (!encryptionService.isValidEncryptedFormat(encryptedIp)) {
            String validationError = "Invalid encrypted IP format";
            log.error("{}: {}", validationError, encryptedIp);
            auditLogService.logSecurityEvent("BLACKLIST_REMOVE_REJECTED", encryptedIp, validationError);
            return Mono.error(new IllegalArgumentException(validationError));
        }

        String redisKey = KeyPrefix.BLACKLIST + encryptedIp;
        String firestoreDocId = encryptedIp;

        Mono<Boolean> redisRemoval = reactiveRedisTemplate.opsForValue().delete(redisKey)
                .onErrorResume(e -> {
                    log.error("Redis deletion failed: {}", e.getMessage());
                    return Mono.just(false);
                });

        Mono<Void> firestoreRemoval = Mono.fromCallable(() -> {
            WriteBatch batch = firestore.batch();
            batch.delete(firestore.collection(FIRESTORE_BLACKLIST_COLLECTION).document(firestoreDocId));
            batch.commit().get();
            return null;
        }).onErrorResume(e -> {
            log.error("Firestore deletion failed: {}", e.getMessage());
            return Mono.empty();
        }).then();

        return Mono.zip(redisRemoval, firestoreRemoval)
                .doOnSuccess(result -> {
                    blacklistCache.remove(encryptedIp);
                    log.info("Removed IP from blacklist (Redis:{}, Firestore:{}): {}",
                            result.getT1(), true, encryptedIp);
                    auditLogService.logSecurityEvent("BLACKLIST_REMOVED", encryptedIp,
                            "Successfully removed from all storage layers");
                    eventPublisher.publishEvent(new BlacklistRemovedEvent(
                            this,
                            encryptedIp,
                            clock.instant(),
                            "Removed from all storage layers",
                            "system"
                    ));
                })
                .doOnError(e -> {
                    String errorMsg = "Failed to remove blacklist status for IP " + encryptedIp;
                    log.error("{}: {}", errorMsg, e.getMessage());
                    auditLogService.logSecurityEvent("BLACKLIST_REMOVE_FAILURE", encryptedIp, errorMsg);
                })
                .then(Mono.fromRunnable(() -> cleanupAfterBlacklistRemoval(encryptedIp)))
                .then();
    }

    /**
     * Adds an identifier to blacklist with reason
     * @param identifier Key to blacklist
     * @param reason Reason for blacklisting
     * @param ttlHours Time to live in hours
     * @return Mono<Boolean> true if successful
     */
    public Mono<Boolean> addToBlacklist(String identifier, String reason, int ttlHours) {
        String redisKey = KeyPrefix.BLACKLIST + identifier;
        BlacklistEntry entry = new BlacklistEntry(identifier, reason, Instant.now(), encryptionService);

        return reactiveRedisTemplate.opsForValue()
                .set(redisKey, entry, Duration.ofHours(ttlHours))
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        blacklistCache.put(identifier, true);
                        auditLogService.logSecurityEvent("BLACKLIST_ADDED", identifier, reason);
                    }
                })
                .onErrorResume(e -> {
                    log.error("Blacklist operation failed: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    // ==================== THREAT DETECTION ====================

    /**
     * Retrieves threat information for a given key
     * @param threatKey Unique threat identifier
     * @return Mono<ThreatInfo> threat information or empty info if not found
     */
    public Mono<ThreatInfo> getThreatInfo(String threatKey) {
        ThreatInfo cachedInfo = threatInfoCache.get(threatKey);
        if (cachedInfo != null) {
            return Mono.just(cachedInfo);
        }

        return reactiveRedisTemplate.opsForValue().get(KeyPrefix.THREAT + threatKey)
                .flatMap(obj -> {
                    if (obj instanceof ThreatInfo) {
                        ThreatInfo info = (ThreatInfo) obj;
                        threatInfoCache.put(threatKey, info);
                        return Mono.just(info);
                    }
                    return Mono.empty();
                })
                .switchIfEmpty(Mono.just(new ThreatInfo(threatKey)))
                .timeout(Duration.ofSeconds(operationTimeoutSeconds))
                .onErrorResume(e -> {
                    log.error("Threat info lookup failed for {}: {}", threatKey, e.getMessage());
                    metricsService.incrementCounter("threat.lookup.failure");
                    return Mono.just(new ThreatInfo(threatKey));
                });
    }

    /**
     * Caches threat detection result
     * @param cacheKey Unique cache key
     * @param isThreat Whether this is a threat
     * @param ttlSeconds Cache duration in seconds
     * @return Mono<Boolean> true if cached successfully
     */
    public Mono<Boolean> cacheThreatResult(String cacheKey, Boolean isThreat, long ttlSeconds) {
        return reactiveRedisTemplate.opsForValue()
                .set(KeyPrefix.THREAT + cacheKey, isThreat, Duration.ofSeconds(ttlSeconds))
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        log.debug("Threat result cached for key: {}", cacheKey);
                    }
                })
                .doOnError(e -> log.error("Error caching threat result for {}: {}", cacheKey, e.getMessage()));
    }

    /**
     * Caches comprehensive threat information
     * @param threatInfo Threat information to cache
     * @param ttlSeconds Cache duration in seconds
     * @return Mono<Boolean> true if cached successfully
     */
    public Mono<Boolean> storeThreatInfo(ThreatInfo threatInfo, long ttlSeconds) {
        String key = KeyPrefix.THREAT + threatInfo.getThreatKey();

        return reactiveRedisTemplate.opsForValue()
                .set(key, threatInfo, Duration.ofSeconds(ttlSeconds))
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        threatInfoCache.put(threatInfo.getThreatKey(), threatInfo);
                        metricsService.incrementCounter("threat.cache.success");
                        log.debug("Stored threat info for {}", threatInfo.getThreatKey());
                    }
                })
                .onErrorResume(e -> {
                    log.error("Failed to store threat info: {}", e.getMessage());
                    metricsService.incrementCounter("threat.cache.failure");
                    return Mono.just(false);
                });
    }

    // ==================== REQUEST PATTERN TRACKING ====================

    /**
     * Checks if request pattern appears suspicious
     * @param userId User making the request
     * @param endpoint Endpoint being accessed
     * @return Mono<Boolean> true if suspicious
     */
    public Mono<Boolean> hasAnomalousRequestPattern(String userId, String endpoint) {
        String key = buildRequestPatternKey(userId, endpoint);

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

    /**
     * Records a request pattern for anomaly detection
     * @param userId User making the request
     * @param endpoint Endpoint being accessed
     * @return Mono<Void> completing when recorded
     */
    public Mono<Void> trackRequestPattern(String userId, String endpoint) {
        String key = buildRequestPatternKey(userId, endpoint);

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
                .doOnError(e -> log.error("Failed to track request pattern: {}", e.getMessage()));
    }

    /**
     * Gets request pattern for a user and endpoint
     * @param userId User ID
     * @param endpoint Endpoint path
     * @return Mono<RequestPattern> pattern information
     */
    public Mono<RequestPattern> getRequestPattern(String userId, String endpoint) {
        String key = buildRequestPatternKey(userId, endpoint);

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(result -> {
                    if (result instanceof RequestPattern) {
                        return Mono.just((RequestPattern) result);
                    }
                    return Mono.empty();
                })
                .switchIfEmpty(Mono.just(new RequestPattern(userId, endpoint, 0, 0, Instant.now())))
                .doOnError(e -> log.error("Error retrieving request pattern for {}: {}", key, e.getMessage()));
    }

    // ==================== DEVICE MANAGEMENT ====================

    /**
     * Stores device information with security tracking
     * @param deviceInfo Device information to store
     * @return Mono<Boolean> true if stored successfully
     */
    public Mono<Boolean> registerDevice(DeviceInfo deviceInfo) {
        String key = buildDeviceKey(deviceInfo.getUserId(), deviceInfo.getDeviceFingerprint());

        return reactiveRedisTemplate.opsForValue()
                .set(key, deviceInfo, Duration.ofDays(30))
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        auditLogService.logDeviceEvent("DEVICE_REGISTERED", deviceInfo);
                    }
                })
                .onErrorResume(e -> {
                    log.error("Device registration failed: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Retrieves device information
     * @param userId User ID
     * @param deviceFingerprint Device fingerprint
     * @return Mono<DeviceInfo> device information if found
     */
    public Mono<DeviceInfo> getDevice(String userId, String deviceFingerprint) {
        String key = buildDeviceKey(userId, deviceFingerprint);

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(obj -> {
                    if (obj instanceof DeviceInfo) {
                        return Mono.just((DeviceInfo) obj);
                    }
                    return Mono.empty();
                })
                .timeout(Duration.ofSeconds(2))
                .onErrorResume(e -> {
                    log.warn("Device lookup failed: {}", e.getMessage());
                    return Mono.empty();
                });
    }

    /**
     * Gets all devices for a user
     * @param userId User ID
     * @return Mono<List<DeviceInfo>> list of devices
     */
    public Mono<List<DeviceInfo>> getAllUserDevices(String userId) {
        if (!StringUtils.hasText(userId)) {
            return Mono.error(new IllegalArgumentException("User ID cannot be empty"));
        }

        String devicePattern = KeyPrefix.DEVICE + userId + ":*";

        return reactiveRedisTemplate.keys(devicePattern)
                .flatMap(key -> reactiveRedisTemplate.opsForValue().get(key))
                .filter(DeviceInfo.class::isInstance)
                .map(DeviceInfo.class::cast)
                .collectList()
                .timeout(Duration.ofSeconds(3))
                .doOnSuccess(devices -> log.debug("Retrieved {} devices for user {}", devices.size(), userId))
                .doOnError(e -> log.error("Failed to get devices for user {}: {}", userId, e.getMessage()))
                .onErrorResume(e -> {
                    metricsService.incrementCounter("device.lookup.failure");
                    return Mono.just(List.of());
                });
    }

    /**
     * Gets paginated and filtered devices
     * @param userId User ID
     * @param page Page number (0-indexed)
     * @param size Page size
     * @param filter Optional filter predicate
     * @return Mono<DevicePage> paginated results
     */
    public Mono<DevicePage> getUserDevices(String userId, int page, int size, DeviceFilter filter) {
        return getAllUserDevices(userId)
                .map(devices -> {
                    List<DeviceInfo> filtered = devices.stream()
                            .filter(device -> filter == null || filter.matches(device))
                            .toList();

                    int total = filtered.size();
                    int fromIndex = Math.min(page * size, total);
                    int toIndex = Math.min((page + 1) * size, total);

                    return new DevicePage(
                            filtered.subList(fromIndex, toIndex),
                            page,
                            size,
                            total
                    );
                });
    }

    /**
     * Updates device information
     * @param deviceInfo Updated device information
     * @return Mono<Boolean> true if updated successfully
     */
    public Mono<Boolean> updateDevice(DeviceInfo deviceInfo) {
        String key = buildDeviceKey(deviceInfo.getUserId(), deviceInfo.getDeviceFingerprint());

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
     * Removes a specific device
     * @param userId User ID
     * @param deviceFingerprint Device fingerprint
     * @return Mono<Boolean> true if device was removed
     */
    public Mono<Boolean> removeDevice(String userId, String deviceFingerprint) {
        if (!StringUtils.hasText(userId) || !StringUtils.hasText(deviceFingerprint)) {
            return Mono.error(new IllegalArgumentException("User ID and device fingerprint cannot be empty"));
        }

        String key = buildDeviceKey(userId, deviceFingerprint);

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(device -> {
                    if (device instanceof DeviceInfo) {
                        return reactiveRedisTemplate.delete(key)
                                .doOnSuccess(deleted -> {
                                    if (deleted > 0) {
                                        log.info("Removed device {} for user {}", deviceFingerprint, userId);
                                        auditLogService.logSecurityEvent("DEVICE_REMOVED", userId,
                                                Map.of("deviceFingerprint", deviceFingerprint, "action", "manual_removal").toString());
                                        metricsService.incrementCounter("device.removed");
                                    }
                                });
                    }
                    return Mono.just(false);
                })
                .defaultIfEmpty(false)
                .timeout(Duration.ofSeconds(3))
                .onErrorResume(e -> {
                    log.error("Failed to remove device {} for user {}: {}", deviceFingerprint, userId, e.getMessage());
                    metricsService.incrementCounter("device.removal.failed");
                    return Mono.just(false);
                }).hasElement();
    }

    /**
     * Removes device and returns its information
     * @param userId User ID
     * @param deviceFingerprint Device fingerprint
     * @return Mono<DeviceInfo> removed device info
     */
    public Mono<DeviceInfo> removeAndGetDevice(String userId, String deviceFingerprint) {
        String key = buildDeviceKey(userId, deviceFingerprint);

        return reactiveRedisTemplate.opsForValue().get(key)
                .flatMap(device -> {
                    if (device instanceof DeviceInfo) {
                        DeviceInfo deviceInfo = (DeviceInfo) device;
                        return reactiveRedisTemplate.delete(key)
                                .flatMap(deleted -> deleted > 0 ? Mono.just(deviceInfo) : Mono.empty());
                    }
                    return Mono.empty();
                })
                .timeout(Duration.ofSeconds(3))
                .doOnSuccess(device -> log.info("Removed and returned device {}", deviceFingerprint))
                .doOnError(e -> log.error("Device removal failed: {}", e.getMessage()));
    }

    /**
     * Removes all devices except one
     * @param userId User ID
     * @param deviceToKeep Device fingerprint to keep
     * @return Mono<Integer> count of removed devices
     */
    public Mono<Integer> revokeAllDevicesExcept(String userId, String deviceToKeep) {
        return getAllUserDevices(userId)
                .flatMapMany(Flux::fromIterable)
                .filter(device -> !device.getDeviceFingerprint().equals(deviceToKeep))
                .flatMap(device -> removeDevice(userId, device.getDeviceFingerprint()))
                .filter(Boolean::booleanValue)
                .collectList()
                .map(List::size)
                .doOnSuccess(count -> log.info("Revoked {} devices for user {}", count, userId))
                .doOnError(e -> log.error("Bulk device revocation failed: {}", e.getMessage()))
                .defaultIfEmpty(0);
    }

    /**
     * Removes devices inactive for specified days
     * @param userId User ID
     * @param inactiveDays Days of inactivity threshold
     * @return Mono<Integer> count of removed devices
     */
    public Mono<Integer> cleanupInactiveDevices(String userId, int inactiveDays) {
        Instant cutoffTime = Instant.now().minus(inactiveDays, ChronoUnit.DAYS);

        return getAllUserDevices(userId)
                .flatMapMany(Flux::fromIterable)
                .filter(device -> device.getLastActive().isBefore(cutoffTime))
                .flatMap(device -> removeDevice(userId, device.getDeviceFingerprint()))
                .filter(Boolean::booleanValue)
                .collectList()
                .map(List::size)
                .doOnSuccess(count -> log.info("Cleaned up {} inactive devices for user {}", count, userId))
                .doOnError(e -> log.error("Inactive device cleanup failed: {}", e.getMessage()));
    }

    /**
     * Revokes all other devices (for logout all)
     * @param userId User ID
     * @param currentDevice Current device to keep
     * @return Mono<Void> completing when done
     */
    public Mono<Void> revokeOtherDevices(String userId, String currentDevice) {
        return getAllUserDevices(userId)
                .flatMap(devices -> Flux.fromIterable(devices)
                        .filter(device -> !device.getDeviceFingerprint().equals(currentDevice))
                        .flatMap(device -> reactiveRedisTemplate.delete(
                                buildDeviceKey(userId, device.getDeviceFingerprint())
                        ))
                        .then())
                .doOnSuccess(__ -> log.info("Revoked all other devices for user {}", userId))
                .doOnError(e -> log.error("Failed to revoke devices for user {}: {}", userId, e.getMessage()));
    }

    /**
     * Gets device count for a user
     * @param userId User ID
     * @return Mono<Long> device count
     */
    public Mono<Long> getDeviceCount(String userId) {
        String pattern = KeyPrefix.DEVICE + userId + ":*";

        return reactiveRedisTemplate.keys(pattern)
                .count()
                .timeout(Duration.ofSeconds(2))
                .defaultIfEmpty(0L);
    }

    // ==================== GENERAL KEY-VALUE OPERATIONS ====================

    /**
     * Stores a value with TTL
     * @param key Key name
     * @param value Value to store
     * @param ttl Time to live
     * @return Mono<Void> completing when stored
     */
    public Mono<Void> storeValue(String key, Object value, Duration ttl) {
        validateKey(key);
        validateValue(value);

        String prefixedKey = applyKeyPrefix(key);

        return Mono.fromRunnable(() -> {
            try {
                redisTemplate.opsForValue().set(prefixedKey, value, ttl);
                log.info("Stored key {} with TTL {}", prefixedKey, ttl);
                auditLogService.logDataOperation("REDIS_SET", prefixedKey, "Success");
            } catch (Exception e) {
                String errorMsg = String.format("Failed to store key %s", prefixedKey);
                log.error("{}: {}", errorMsg, e.getMessage());
                auditLogService.logDataOperation("REDIS_SET_FAILURE", prefixedKey, errorMsg);
                throw new RedisOperationException(errorMsg, e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Retrieves a value
     * @param key Key name
     * @return Mono<Object> value if found, empty otherwise
     */
    /**
     * Retrieves a stored value
     */
    public Mono<Object> getValue(String key) {
        validateKey(key);
        String prefixedKey = applyKeyPrefix(key);

        return Mono.fromCallable(() -> {
            try {
                Object value = redisTemplate.opsForValue().get(prefixedKey);
                auditLogService.logDataOperation("REDIS_GET", prefixedKey, "Success");
                return value;
            } catch (SerializationException e) {
                String msg = "Serialization error for key " + prefixedKey;
                log.error("{}: {}", msg, e.getMessage());
                auditLogService.logDataOperation("REDIS_GET_SERIALIZATION_FAILURE", prefixedKey, msg);
                throw new RedisOperationException(msg, e);
            } catch (Exception e) {
                String msg = "Failed to retrieve key " + prefixedKey;
                log.error("{}: {}", msg, e.getMessage());
                auditLogService.logDataOperation("REDIS_GET_FAILURE", prefixedKey, msg);
                throw new RedisOperationException(msg, e);
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Deletes a key
     */
    public Mono<Boolean> deleteValue(String key) {
        validateKey(key);
        String prefixedKey = applyKeyPrefix(key);

        return Mono.fromCallable(() -> {
            try {
                Boolean result = redisTemplate.delete(prefixedKey);
                auditLogService.logDataOperation("REDIS_DELETE", prefixedKey, "Success");
                return Boolean.TRUE.equals(result);
            } catch (Exception e) {
                String msg = "Failed to delete key " + prefixedKey;
                log.error("{}: {}", msg, e.getMessage());
                auditLogService.logDataOperation("REDIS_DELETE_FAILURE", prefixedKey, msg);
                throw new RedisOperationException(msg, e);
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ============================================================
    // =============== INTERNAL UTILITIES & HELPERS ===============
    // ============================================================

    private void validateKey(String key) {
        if (!StringUtils.hasText(key)) {
            throw new IllegalArgumentException("Key cannot be empty");
        }
    }

    private void validateValue(Object value) {
        if (value == null) {
            throw new IllegalArgumentException("Cannot store null value in Redis");
        }
    }

    private String applyKeyPrefix(String key) {
        return keyPrefix + key;
    }

    private String decryptIp(String encryptedIp) {
        try {
            return encryptionService.decrypt(encryptedIp);
        } catch (Exception e) {
            String msg = "Failed to decrypt IP";
            log.error("{}: {}", msg, e.getMessage());
            throw new IllegalArgumentException(msg);
        }
    }

    private void validateEncryptedIp(String encryptedIp) {
        if (!encryptionService.isValidEncryptedFormat(encryptedIp)) {
            throw new IllegalArgumentException("Invalid encrypted IP format");
        }
    }

    private void cleanupAfterBlacklistRemoval(String encryptedIp) {
        blacklistCache.remove(encryptedIp);
        metricsService.incrementCounter("blacklist.removal.cleaned");
        log.debug("Cleanup completed for removed IP {}", encryptedIp);
    }

    private String buildRequestPatternKey(String userId, String endpoint) {
        return KeyPrefix.REQUEST_PATTERN + userId + ":" + endpoint;
    }

    private String buildDeviceKey(String userId, String deviceFingerprint) {
        return KeyPrefix.DEVICE + userId + ":" + deviceFingerprint;
    }

    // ============================================================
    // ======================= DATA CLASSES ========================
    // ============================================================

    @Data
    public static class DevicePage {
        private final List<DeviceInfo> devices;
        private final int page;
        private final int size;
        private final int total;
    }

    @FunctionalInterface
    public interface DeviceFilter {
        boolean matches(DeviceInfo deviceInfo);
    }
}
