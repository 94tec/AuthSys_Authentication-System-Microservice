package com.techStack.authSys.service.security;

import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.sucurity.RateLimiterService;
import com.techStack.authSys.service.observability.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class ThreatDetectionService {
    private static final Logger logger = LoggerFactory.getLogger(ThreatDetectionService.class);

    private final WebClient webClient;
    private final RedisSecurityService redisService;
    private final AuditLogService auditLogService;
    private final RateLimiterService rateLimiterService;
    private final MetricsService metricsService;

    @Value("${threat.detection.api.url}")
    private String threatApiUrl;

    @Value("${threat.detection.api.key}")
    private String apiKey;

    @Value("${threat.detection.cache.ttl:3600}") // 1 hour
    private long cacheTtlSeconds;

    @Value("${threat.detection.enabled:true}")
    private boolean threatDetectionEnabled;

    // Local cache for quick threat lookups
    private final Map<String, Boolean> threatCache = new ConcurrentHashMap<>();

    /**
     * Checks device reputation and IP threat level
     */
    public Mono<Boolean> checkDeviceReputation(String deviceFingerprint, String ipAddress) {
        if (!threatDetectionEnabled) {
            return Mono.just(false);
        }

        return rateLimiterService.checkThreatApiRateLimit(ipAddress)
                .then(Mono.defer(() -> {
                    // Check local cache first
                    String cacheKey = deviceFingerprint + "|" + ipAddress;
                    Boolean cachedResult = threatCache.get(cacheKey);
                    if (cachedResult != null) {
                        return Mono.just(cachedResult);
                    }

                    // Check Redis cache
                    return redisService.getThreatInfo(cacheKey)
                            .map(threatInfo -> {
                                boolean isThreat = threatInfo != null && threatInfo.isThreat(); // Extract boolean value
                                threatCache.put(cacheKey, isThreat);
                                return isThreat;
                            })
                            .switchIfEmpty(
                                    callThreatDetectionApi(deviceFingerprint, ipAddress)
                                            .doOnNext(result -> {
                                                // Cache results
                                                redisService.cacheThreatResult(cacheKey, result, cacheTtlSeconds)
                                                        .subscribeOn(Schedulers.boundedElastic())
                                                        .subscribe();
                                                threatCache.put(cacheKey, result);
                                            })
                            );

                }))
                .timeout(Duration.ofSeconds(3))
                .onErrorResume(e -> {
                    logger.error("Threat detection failed: {}", e.getMessage(), e);
                    metricsService.incrementCounter("threat.detection.failure");
                    return Mono.just(false); // Fail-safe
                });
    }


    /**
     * Calls external threat intelligence API
     */
    private Mono<Boolean> callThreatDetectionApi(String deviceFingerprint, String ipAddress) {
        return webClient.post()
                .uri(STR."\{threatApiUrl}/check")
                .header("X-API-KEY", apiKey)
                .bodyValue(buildThreatRequest(deviceFingerprint, ipAddress))
                .retrieve()
                .bodyToMono(ThreatApiResponse.class)
                .map(response -> {
                    boolean isThreat = response.isMalicious() || response.isBot() || response.isVpn();

                    if (isThreat) {
                        auditLogService.logSecurityEvent(
                                "THREAT_DETECTED",
                                ipAddress,
                                Map.of(
                                        "deviceFingerprint", deviceFingerprint,
                                        "threatType", response.getThreatType(),
                                        "confidence", response.getConfidenceScore()
                                ).toString()
                        );
                    }

                    return isThreat;
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Checks if IP is in any threat database
     */
    public Mono<Boolean> checkIpReputation(String ipAddress) {
        return checkDeviceReputation("unknown", ipAddress);
    }

    /**
     * Checks if request pattern is suspicious
     */
    public Mono<Boolean> detectSuspiciousPattern(String userId, String endpoint, String ipAddress) {
        return redisService.getRequestPattern(userId, endpoint)
                .map(pattern -> {
                    // Implement your anomaly detection logic here
                    boolean isSuspicious = pattern.getRequestCount() > 100 &&
                            pattern.getTimeWindow() < 10;

                    if (isSuspicious) {
                        auditLogService.logSecurityEvent(
                                "SUSPICIOUS_PATTERN_DETECTED",
                                userId,
                                Map.of(
                                        "endpoint", endpoint,
                                        "ipAddress", ipAddress,
                                        "requestCount", pattern.getRequestCount(),
                                        "timeWindow", pattern.getTimeWindow()
                                ).toString()
                        );
                    }

                    return isSuspicious;
                })
                .defaultIfEmpty(false);
    }

    private Map<String, Object> buildThreatRequest(String deviceFingerprint, String ipAddress) {
        return Map.of(
                "deviceFingerprint", deviceFingerprint,
                "ipAddress", ipAddress,
                "timestamp", System.currentTimeMillis()
        );
    }

    // Inner class for API response
    private static class ThreatApiResponse {
        private boolean malicious;
        private boolean bot;
        private boolean vpn;
        private String threatType;
        private double confidenceScore;

        // Getters
        public boolean isMalicious() { return malicious; }
        public boolean isBot() { return bot; }
        public boolean isVpn() { return vpn; }
        public String getThreatType() { return threatType; }
        public double getConfidenceScore() { return confidenceScore; }
    }
}