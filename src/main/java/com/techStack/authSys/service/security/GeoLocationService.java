package com.techStack.authSys.service.security;

import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.service.observability.AuditLogService;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class GeoLocationService {
    private static final Set<String> LOCALHOST_IPS = Set.of("127.0.0.1", "0:0:0:0:0:0:0:1", "::1");
    private static final String DEFAULT_COUNTRY = "KE"; // Default country for localhost

    private final WebClient webClient;
    private final MetricsService metricsService;
    private final AuditLogService auditLogService;

    @Value("${geo.allowed-countries:KE,UG,TZ,RW,BI}")
    private String allowedCountriesRaw;
    private List<String> allowedCountries;

    @Value("${geo.api.timeout:3000}")
    private long apiTimeout;

    @Value("${geo.api.url:http://ip-api.com/json}")
    private String apiUrl;

    @Value("${geo.enabled:true}")
    private boolean geoValidationEnabled;

    @Value("${geo.allow-localhost:true}")
    private boolean allowLocalhost;

    // Cache for known IPs to reduce API calls
    private final ConcurrentHashMap<String, Boolean> ipCache = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {

    }

    public Mono<Boolean> validateLocation(String ipAddress) {
        if (!geoValidationEnabled) {
            return Mono.just(true);
        }

        ipAddress = normalizeIp(ipAddress);

        // Check cache first
        Boolean cachedResult = ipCache.get(ipAddress);
        if (cachedResult != null) {
            return Mono.just(cachedResult);
        }

        // Handle localhost specially
        if (isLocalhost(ipAddress)) {
            boolean allowed = allowLocalhost;
            ipCache.put(ipAddress, allowed);
            log.debug("Localhost IP {} treated as {}", ipAddress, allowed ? "allowed" : "blocked");
            return Mono.just(allowed);
        }

        if (!isValidIp(ipAddress)) {
            log.warn("Invalid IP address format: {}", ipAddress);
            auditLogService.logSecurityEvent("GEO_VALIDATION_FAILED", ipAddress, "Invalid IP format");
            return Mono.just(false);
        }

        String finalIpAddress = ipAddress;
        String finalIpAddress1 = ipAddress;
        return webClient.get()
                .uri("{}/{}/?fields=status,countryCode,proxy,hosting", apiUrl, ipAddress)
                .retrieve()
                .bodyToMono(GeoLocationResponseDTO.class)
                .timeout(Duration.ofMillis(apiTimeout))
                .flatMap(response -> {
                    boolean isValid = validateResponse(finalIpAddress, response);
                    ipCache.put(finalIpAddress, isValid); // Cache valid responses
                    return Mono.just(isValid);
                })
                .onErrorResume(e -> handleGeoApiError(finalIpAddress1, e));
    }

    private boolean validateResponse(String ipAddress, GeoLocationResponseDTO response) {
        if (response == null || !"success".equalsIgnoreCase(response.getStatus())) {
            log.warn("Geo-lookup failed for IP: {}", ipAddress);
            auditLogService.logSecurityEvent("GEO_VALIDATION_FAILED", ipAddress, "API lookup failed");
            return false;
        }

        boolean isAllowed = isAllowedCountry(response.getCountryCode()) && !isSuspiciousNetwork(response);
        log.info("IP validation - IP: {}, Country: {}, Proxy: {}, Hosting: {}, Allowed: {}",
                ipAddress, response.getCountryCode(), response.isProxy(), response.isHosting(), isAllowed);

        if (!isAllowed) {
            auditLogService.logSecurityEvent("GEO_BLOCKED", ipAddress,
                    String.format("Country: %s, Proxy: %s, Hosting: %s",
                            response.getCountryCode(), response.isProxy(), response.isHosting()));
        }

        return isAllowed;
    }

    private Mono<Boolean> handleGeoApiError(String ipAddress, Throwable e) {
        log.error("Geo-API error for IP {}: {}", ipAddress, e.getMessage());
        metricsService.incrementCounter("geo_api_error", "ip", ipAddress);

        // Fail secure - only allow if IP is in cache with true value
        boolean fallbackResult = Boolean.TRUE.equals(ipCache.get(ipAddress));
        if (!fallbackResult) {
            auditLogService.logSecurityEvent("GEO_FALLBACK", ipAddress,
                    "API failed, using cached result: " + fallbackResult);
        }
        return Mono.just(fallbackResult);
    }

    private boolean isLocalhost(String ipAddress) {
        return LOCALHOST_IPS.contains(ipAddress);
    }

    private boolean isValidIp(String ipAddress) {
        return ipAddress != null && ipAddress.matches(
                "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    }

    private boolean isAllowedCountry(String countryCode) {
        return countryCode != null && allowedCountries.contains(countryCode.toUpperCase());
    }

    private boolean isSuspiciousNetwork(GeoLocationResponseDTO response) {
        return response.isProxy() || response.isHosting();
    }

    private String normalizeIp(String ip) {
        return LOCALHOST_IPS.contains(ip) ? "127.0.0.1" : ip;
    }

    // Cache management
    public void clearCache() {
        ipCache.clear();
        log.info("Geo location cache cleared");
    }

    public void addToCache(String ipAddress, boolean allowed) {
        ipCache.put(normalizeIp(ipAddress), allowed);
    }

    @Getter
    private static class GeoLocationResponseDTO {
        private String status;
        private String countryCode;
        private boolean proxy;
        private boolean hosting;
    }
}