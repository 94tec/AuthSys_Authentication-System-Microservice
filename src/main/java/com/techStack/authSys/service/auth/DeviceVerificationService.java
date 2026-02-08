package com.techStack.authSys.service.auth;

import com.google.cloud.firestore.Firestore;
import com.techStack.authSys.exception.auth.DeviceVerificationException;
import com.techStack.authSys.models.session.DeviceInfo;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.RedisSecurityService;
import com.techStack.authSys.service.security.ThreatDetectionService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
@Service
@RequiredArgsConstructor
public class DeviceVerificationService {

    private static final Logger logger = LoggerFactory.getLogger(DeviceVerificationService.class);

    private final AuditLogService auditLogService;
    private final ThreatDetectionService threatDetectionService;
    private final RedisSecurityService redisService;
    private final Firestore firestore;

    private static final Pattern IPV4_PATTERN = Pattern.compile("^([0-9]{1,3}\\.){3}[0-9]{1,3}$");
    private static final Pattern IPV6_PATTERN = Pattern.compile("^[0-9a-fA-F:]+$");

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
    public Mono<Boolean> verifyDevice(
            String userId,
            String deviceFingerprint,
            String ipAddress,
            String userAgent
    ) {
        if (!verificationEnabled) {
            return Mono.just(true);
        }

        return Mono.defer(() -> {

            if (!isValidDeviceFingerprint(deviceFingerprint)) {
                logger.warn("Invalid device fingerprint format: {}", deviceFingerprint);
                return Mono.error(new DeviceVerificationException("Invalid device identifier"));
            }

            return threatDetectionService.checkDeviceReputation(deviceFingerprint, ipAddress)
                    .flatMap(isMalicious -> {
                        if (isMalicious) {
                            auditLogService.logSecurityEvent(
                                    "MALICIOUS_DEVICE_DETECTED",
                                    ipAddress,
                                    Map.of(
                                            "deviceFingerprint", deviceFingerprint,
                                            "userAgent", userAgent
                                    ).toString()
                            );
                            return Mono.error(new DeviceVerificationException("Device flagged as malicious"));
                        }

                        return checkKnownDevice(userId, deviceFingerprint, ipAddress, userAgent);
                    })
                    .timeout(Duration.ofSeconds(3))
                    .onErrorResume(e -> {
                        logger.error("Device verification failed: {}", e.getMessage(), e);
                        return Mono.error(new DeviceVerificationException("Device verification unavailable"));
                    });
        });
    }

    /**
     * Generates ONE device fingerprint
     */
    public String generateDeviceFingerprint(String ipAddress, String userAgent) {
        try {
            logger.debug("Generating device fingerprint for IP: {}, UserAgent: {}", ipAddress, userAgent);

            if (!isValidInput(ipAddress, userAgent)) {
                logger.warn("Invalid input for fingerprint generation - IP: {}, UserAgent: {}", ipAddress, userAgent);
                return UNKNOWN_DEVICE;
            }

            String normalizedIp = normalizeIp(ipAddress);
            String normalizedUserAgent = userAgent.trim().toLowerCase();

            String fingerprint = DigestUtils.sha256Hex(normalizedIp + "|" + normalizedUserAgent);

            logger.debug("Generated fingerprint: {}", fingerprint);
            return fingerprint;

        } catch (Exception e) {
            logger.error("Device fingerprint generation failed - IP: {}, UserAgent: {}", ipAddress, userAgent, e);
            return UNKNOWN_DEVICE;
        }
    }

    /**
     * Safely extracts the real client IP address from ServerWebExchange.
     */
    public String extractClientIp(ServerWebExchange exchange) {
        try {
            ServerHttpRequest request = exchange.getRequest();

            String forwardedIps = request.getHeaders().getFirst("X-Forwarded-For");
            logger.info("X-Forwarded-For: {}", forwardedIps);

            if (StringUtils.hasText(forwardedIps)) {
                String[] ips = forwardedIps.split(",");
                for (String ip : ips) {
                    String cleanIp = ip.trim();
                    if (isValidIp(cleanIp)) {
                        String normalized = normalizeIp(cleanIp);
                        logger.info("Resolved client IP from X-Forwarded-For: {}", normalized);
                        return normalized;
                    }
                }
            }

            InetSocketAddress remote = request.getRemoteAddress();
            if (remote != null && remote.getAddress() != null) {
                String ip = remote.getAddress().getHostAddress();
                String normalized = normalizeIp(ip);

                logger.info("Resolved client IP from remote address: {}", normalized);
                return normalized;
            }

            logger.warn("Could not resolve client IP, returning fallback.");
            return FALLBACK_IP;

        } catch (Exception ex) {
            logger.warn("IP extraction failed", ex);
            return FALLBACK_IP;
        }
    }

    public String normalizeIp(String ip) {
        if (!StringUtils.hasText(ip)) {
            return FALLBACK_IP;
        }

        ip = ip.trim();

        if ("0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip)) {
            return "127.0.0.1";
        }

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

                firestore.collection("users")
                        .document(userId)
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
    public Mono<Void> registerTrustedDevice(
            String userId,
            String deviceFingerprint,
            String ipAddress,
            String userAgent
    ) {
        return Mono.defer(() -> {

            Instant now = Instant.now();

            DeviceInfo deviceInfo = DeviceInfo.builder()
                    .deviceFingerprint(deviceFingerprint)
                    .userId(userId)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .createdAt(now)
                    .expiresAt(now.plusSeconds(cacheTtlSeconds))
                    .build();

            return redisService.registerDevice(deviceInfo)
                    .then(Mono.fromRunnable(() ->
                            knownDevicesCache.put(buildCacheKey(userId, deviceFingerprint), deviceInfo)
                    ))
                    .then(checkAndEnforceDeviceLimit(userId));
        });
    }

    /**
     * Checks if device is known and trusted
     */
    private Mono<Boolean> checkKnownDevice(
            String userId,
            String deviceFingerprint,
            String ipAddress,
            String userAgent
    ) {
        DeviceInfo cachedInfo = knownDevicesCache.values().stream()
                .filter(info -> info.getDeviceFingerprint().equals(deviceFingerprint))
                .findFirst()
                .orElse(null);

        if (cachedInfo != null) {
            return Mono.just(true);
        }

        return redisService.getDevice(userId, deviceFingerprint)
                .map(deviceInfo -> {

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

    private Mono<Void> checkAndEnforceDeviceLimit(String userId) {
        return redisService.getAllUserDevices(userId)
                .flatMap(devices -> {
                    if (devices.size() > maxDevicesPerUser) {

                        DeviceInfo oldest = devices.stream()
                                .sorted((d1, d2) -> d1.getRegistrationDate().compareTo(d2.getRegistrationDate()))
                                .findFirst()
                                .orElse(null);

                        if (oldest != null) {
                            return redisService.removeDevice(userId, oldest.getDeviceFingerprint())
                                    .then(Mono.fromRunnable(() ->
                                            knownDevicesCache.remove(buildCacheKey(userId, oldest.getDeviceFingerprint()))
                                    ));
                        }
                    }
                    return Mono.empty();
                });
    }

    private boolean isValidDeviceFingerprint(String fingerprint) {
        return fingerprint != null && fingerprint.matches("^[a-fA-F0-9]{64}$");
    }

    private boolean isValidInput(String ip, String userAgent) {
        return StringUtils.hasText(ip) && StringUtils.hasText(userAgent);
    }

    private boolean isValidIp(String ipAddress) {
        if (!StringUtils.hasText(ipAddress)) return false;

        ipAddress = normalizeIp(ipAddress);

        String ipv4Pattern = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        String ipv6Pattern = "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$";

        return ipAddress.matches(ipv4Pattern) || ipAddress.matches(ipv6Pattern);
    }

    private String buildCacheKey(String userId, String deviceFingerprint) {
        return userId + ":" + deviceFingerprint;
    }
}

