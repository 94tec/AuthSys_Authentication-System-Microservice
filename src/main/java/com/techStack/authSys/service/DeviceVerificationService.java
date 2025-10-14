package com.techStack.authSys.service;

import com.google.cloud.firestore.Firestore;
import com.google.common.net.InetAddresses;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.exception.DeviceVerificationException;
import com.techStack.authSys.models.DeviceInfo;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class DeviceVerificationService {
    private static final Logger logger = LoggerFactory.getLogger(DeviceVerificationService.class);
    private static final String COLLECTION_NAME = "user_fingerprints";

    private final AuditLogService auditLogService;
    private final ThreatDetectionService threatDetectionService;
    private final RedisService redisService;
    private final Firestore firestore;

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^([0-9]{1,3}\\.){3}[0-9]{1,3}$"
    );
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^[0-9a-fA-F:]+$"
    );
    private static final String FALLBACK_IP = "0.0.0.0";
    private static final String UNKNOWN_DEVICE = "unknown-device";

    @Value("${device.verification.enabled:true}")
    private boolean verificationEnabled;

    @Value("${device.verification.maxDevicesPerUser:5}")
    private int maxDevicesPerUser;

    @Value("${device.verification.cacheTtl:86400}") // 24 hours
    private long cacheTtlSeconds;

    // In-memory cache for known devices (fallback)
    private final Map<String, DeviceInfo> knownDevicesCache = new ConcurrentHashMap<>();

    /**
     * Verifies a device based on fingerprint, IP, and user agent
     */
    public Mono<Boolean> verifyDevice(String userId, String deviceFingerprint, String ipAddress, String userAgent) {
        if (!verificationEnabled) {
            return Mono.just(true);
        }

        return Mono.defer(() -> {
            // Basic validation
            if (!isValidDeviceFingerprint(deviceFingerprint)) {
                logger.warn("Invalid device fingerprint format: {}", deviceFingerprint);
                return Mono.error(new DeviceVerificationException("Invalid device identifier"));
            }

            // Check threat intelligence
            return threatDetectionService.checkDeviceReputation(deviceFingerprint, ipAddress)
                    .flatMap(isMalicious -> {
                        if (isMalicious) {
                            auditLogService.logSecurityEvent(
                                    "MALICIOUS_DEVICE_DETECTED",
                                    ipAddress,
                                    Map.of("deviceFingerprint", deviceFingerprint, "userAgent", userAgent).toString()
                            );
                            return Mono.error(new DeviceVerificationException("Device flagged as malicious"));
                        }

                        // Check if device is known and trusted
                        return checkKnownDevice(userId, deviceFingerprint, ipAddress, userAgent);
                    })
                    .timeout(Duration.ofSeconds(3))
                    .onErrorResume(e -> {
                        logger.error("Device verification failed: {}", e.getMessage());
                        return Mono.error(new DeviceVerificationException("Device verification unavailable"));
                    });
        });
    }
    public String generateDeviceFingerprint(String ipAddress, String userAgent) {
        try {
            logger.debug("Generating device fingerprint for IP: {}, UserAgent: {}", ipAddress, userAgent);

            // Validate inputs
            if (!isValidInput(ipAddress, userAgent)) {
                logger.warn("Invalid input for device fingerprint generation - IP: {}, UserAgent: {}", ipAddress, userAgent);
                return UNKNOWN_DEVICE;
            }

            // Normalize inputs
            String normalizedIp = normalizeIp(ipAddress);
            String normalizedUserAgent = userAgent.trim().toLowerCase();

            // Generate consistent fingerprint
            String input = String.format("%s|%s", normalizedIp, normalizedUserAgent);
            String fingerprint = DigestUtils.sha256Hex(input);

            logger.debug("Generated fingerprint: {}", fingerprint);
            return fingerprint;

        } catch (Exception e) {
            logger.error("Device fingerprint generation failed - IP: {}, UserAgent: {}", ipAddress, userAgent, e);
            return UNKNOWN_DEVICE;
        }
    }
    /**
     * Extracts and validates client IP from request
     */
    public String extractClientIp(ServerWebExchange exchange) {
        try {
            ServerHttpRequest request = exchange.getRequest();

            // Check X-Forwarded-For header first
            String forwardedIps = request.getHeaders().getFirst("X-Forwarded-For");
            logger.info("X-Forwarded-For: {}", forwardedIps);

            if (StringUtils.hasText(forwardedIps)) {
                String[] ips = forwardedIps.split(",");
                for (String ip : ips) {
                    String cleanIp = ip.trim();
                    if (isValidIp(cleanIp)) {
                        String normalizedIp = normalizeIp(cleanIp);
                        logger.info("Resolved client IP from X-Forwarded-For: {}", normalizedIp);
                        return normalizedIp;
                    }
                }
            }

            // Fallback to remote address
            InetSocketAddress remoteAddress = request.getRemoteAddress();
            if (remoteAddress != null && remoteAddress.getAddress() != null) {
                String ip = remoteAddress.getAddress().getHostAddress();
                String normalizedIp = normalizeIp(ip);
                logger.info("Resolved client IP from remote address: {}", normalizedIp);
                return normalizedIp;
            }

            // Default fallback
            logger.warn("Could not resolve client IP, returning fallback IP.");
            return FALLBACK_IP;

        } catch (Exception e) {
            logger.warn("IP extraction failed", e);
            return FALLBACK_IP;
        }
    }

    private boolean isValidInput(String ip, String userAgent) {
        return StringUtils.hasText(ip) && StringUtils.hasText(userAgent);
    }

    private boolean isValidIp(String ipAddress) {
        if (!StringUtils.hasText(ipAddress)) {
            return false;
        }

        ipAddress = normalizeIp(ipAddress);

        // IPv4 pattern
        String ipv4Pattern = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

        // IPv6 pattern (simplified)
        String ipv6Pattern = "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$";

        return ipAddress.matches(ipv4Pattern) || ipAddress.matches(ipv6Pattern);
    }

    public String normalizeIp(String ip) {
        if (!StringUtils.hasText(ip)) {
            return FALLBACK_IP;
        }

        ip = ip.trim();

        // Normalize IPv6 loopback
        if ("0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip)) {
            return "127.0.0.1";
        }

        // Remove IPv6 scope if present
        if (ip.contains("%")) {
            ip = ip.substring(0, ip.indexOf("%"));
        }

        return ip;
    }
    public Mono<Void> saveUserFingerprint(String userId, String fingerprint) {
        return Mono.fromRunnable(() -> {
            try {
                Map<String, Object> fingerprintData = new HashMap<>();
                fingerprintData.put("deviceFingerprint", fingerprint);
                fingerprintData.put("timestamp", System.currentTimeMillis());

                firestore.collection("users") // main collection
                        .document(userId) // user document
                        .collection("fingerprints")
                        .add(fingerprintData)
                        .get();
                logger.info("Stored device fingerprint for user: {}", userId);
            } catch (Exception e) {
                logger.error("Failed to store device fingerprint for user: {}", userId, e);
            }
        });
    }
    /**
     * Registers a new trusted device
     */
    public Mono<Void> registerTrustedDevice(String userId, String deviceFingerprint, String ipAddress, String userAgent) {
        return Mono.defer(() -> {
            DeviceInfo deviceInfo = DeviceInfo.builder()
                    .deviceFingerprint(deviceFingerprint)
                    .userId(userId)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .createdAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(cacheTtlSeconds))
                    .build();


            // Store in Redis
            return redisService.storeDeviceInfo(deviceInfo)
                    .then(Mono.fromRunnable(() ->
                            knownDevicesCache.put(buildCacheKey(userId, deviceFingerprint), deviceInfo)
                    ))
                    .then(checkAndEnforceDeviceLimit(userId));
        });
    }

    /**
     * Checks if device is known and trusted
     */
    private Mono<Boolean> checkKnownDevice(String userId,String deviceFingerprint, String ipAddress, String userAgent) {
        // First check in-memory cache
        DeviceInfo cachedInfo = knownDevicesCache.values().stream()
                .filter(info -> info.getDeviceFingerprint().equals(deviceFingerprint))
                .findFirst()
                .orElse(null);

        if (cachedInfo != null) {
            return Mono.just(true);
        }

        // Fallback to Redis lookup
        return redisService.getDeviceInfo(userId, deviceFingerprint)
                .map(deviceInfo -> {
                    // Validate device context
                    boolean ipMatches = deviceInfo.getIpAddress().equals(ipAddress);
                    boolean userAgentMatches = deviceInfo.getUserAgent().equals(userAgent);

                    if (!ipMatches || !userAgentMatches) {
                        logger.warn("Device context changed - Fingerprint: {}, Old IP: {}, New IP: {}",
                                deviceFingerprint, deviceInfo.getIpAddress(), ipAddress);
                        auditLogService.logSecurityEvent(
                                "DEVICE_CONTEXT_CHANGE",
                                ipAddress,
                                Map.of(
                                        "deviceFingerprint", deviceFingerprint,
                                        "oldIp", deviceInfo.getIpAddress(),
                                        "newIp", ipAddress,
                                        "oldUserAgent", deviceInfo.getUserAgent(),
                                        "newUserAgent", userAgent
                                ).toString()
                        );
                    }

                    return ipMatches && userAgentMatches;
                })
                .defaultIfEmpty(false);
    }

    /**
     * Enforces maximum devices per user
     */
    private Mono<Void> checkAndEnforceDeviceLimit(String userId) {
        return redisService.getUserDevices(userId)
                .flatMap(devices -> {
                    if (devices.size() > maxDevicesPerUser) {
                        // Remove oldest device
                        DeviceInfo oldest = devices.stream()
                                .sorted((d1, d2) -> d1.getRegistrationDate().compareTo(d2.getRegistrationDate()))
                                .findFirst()
                                .orElse(null);

                        if (oldest != null) {
                            return redisService.removeDeviceInfo(userId, oldest.getDeviceFingerprint())
                                    .then(Mono.fromRunnable(() ->
                                            knownDevicesCache.remove(buildCacheKey(userId, oldest.getDeviceFingerprint()))
                                    ));
                        }
                    }
                    return Mono.empty();
                });
    }

    private boolean isValidDeviceFingerprint(String fingerprint) {
        if (fingerprint == null || !fingerprint.matches("^[a-fA-F0-9]{64}$")) {
            logger.warn("Received unexpected device fingerprint: {}", fingerprint);
            return false;
        }
        return true;
    }

    private String buildCacheKey(String userId, String deviceFingerprint) {
        return userId + ":" + deviceFingerprint;
    }
}
