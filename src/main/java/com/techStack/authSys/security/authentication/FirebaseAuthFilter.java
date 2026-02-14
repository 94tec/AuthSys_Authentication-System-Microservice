package com.techStack.authSys.security.authentication;

import com.techStack.authSys.config.security.RateLimitProperties;
import com.techStack.authSys.service.auth.FirebaseAuthenticationManager;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Firebase Authentication Filter
 *
 * Handles JWT token extraction, validation, and rate limiting.
 * Uses Clock for all timestamp operations.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class FirebaseAuthFilter implements WebFilter {

    /* =========================
       Constants
       ========================= */

    private static final Set<String> PUBLIC_PATHS = Set.of(
            // Swagger UI
            "/swagger-ui.html",
            "/swagger-ui/",
            "/v3/api-docs/",
            "/webjars/",

            // Health checks
            "/actuator/",
            "/health/",
            "/favicon.ico",

            // Static resources
            "/static/",
            "/css/",
            "/js/",
            "/images/",

            // Authentication endpoints
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/verify-email",
            "/api/auth/resend-verification",
            "/api/auth/check-email",
            "/api/auth/logout",
            "/api/auth/first-time-setup/",
            "/api/auth/login-otp/",
            "/api/otp/",
            "/api/v1/password-reset/",

            // Super Admin bootstrap
            "/api/super-admin/register",
            "/api/super-admin/login"
    );

    private static final Set<String> SENSITIVE_PATHS = Set.of(
            "/api/auth/login",
            "/api/register",
            "/api/password-reset"
    );

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseAuthenticationManager firebaseAuthenticationManager;
    private final RateLimitProperties rateLimitProperties;
    private final ServerSecurityContextRepository securityContextRepository;
    private final MeterRegistry meterRegistry;
    private final Clock clock;

    /* =========================
       Rate Limiting
       ========================= */

    private Bucket globalRateLimiter;
    private final Map<String, Bucket> ipRateLimiters = new ConcurrentHashMap<>();
    private final Map<String, Instant> ipLastAccessMap = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();

    /* =========================
       Initialization
       ========================= */

    @PostConstruct
    public void init() {
        Instant now = clock.instant();

        this.globalRateLimiter = Bucket.builder()
                .addLimit(Bandwidth.classic(
                        rateLimitProperties.getGlobal(),
                        Refill.intervally(
                                rateLimitProperties.getGlobal(),
                                Duration.ofMinutes(rateLimitProperties.getWindowMinutes())
                        )
                ))
                .build();

        cleanupExecutor.scheduleAtFixedRate(this::cleanupOldRateLimiters, 1, 1, TimeUnit.HOURS);
        meterRegistry.gauge("auth.rate_limit.ips", ipRateLimiters, Map::size);

        log.info("FirebaseAuthFilter initialized at {}", now);
    }

    @PreDestroy
    public void shutdown() {
        Instant now = clock.instant();
        cleanupExecutor.shutdown();
        log.info("FirebaseAuthFilter shutdown at {}", now);
    }

    /* =========================
       Filter Implementation
       ========================= */

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String clientIp = getClientIp(request);
        Instant now = clock.instant();

        // ✅ Check if path is public - skip authentication
        if (isPublicPath(path)) {
            log.debug("Public path accessed: {} from IP: {} at {}", path, clientIp, now);
            return chain.filter(exchange);
        }

        log.debug("Protected path accessed: {} from IP: {} at {}", path, clientIp, now);

        // ✅ Check global rate limit
        if (!globalRateLimiter.tryConsume(1)) {
            meterRegistry.counter("auth.rate_limit.global_hits").increment();
            log.warn("⚠️ Global rate limit exceeded for IP: {} at {}", clientIp, now);
            return respondWithTooManyRequests(exchange);
        }

        // ✅ Get or create IP-specific rate limiter
        Bucket ipBucket = getOrCreateIpBucket(clientIp, path, now);

        // ✅ Check IP-specific rate limit
        if (!ipBucket.tryConsume(1)) {
            meterRegistry.counter("auth.rate_limit.ip_hits", "ip", clientIp).increment();
            log.warn("⚠️ Rate limit exceeded for IP: {} on path: {} at {}", clientIp, path, now);
            return respondWithTooManyRequests(exchange);
        }

        // ✅ Extract and validate JWT token
        return extractTokenFromRequest(request)
                .map(token -> new UsernamePasswordAuthenticationToken(token, token))
                .flatMap(firebaseAuthenticationManager::authenticate)
                .flatMap(auth -> {
                    log.debug("✅ Authentication successful for IP: {} at {}", clientIp, now);
                    meterRegistry.counter("auth.successes").increment();
                    return securityContextRepository.save(exchange, new SecurityContextImpl(auth))
                            .then(chain.filter(exchange));
                })
                .switchIfEmpty(chain.filter(exchange))
                .onErrorResume(e -> {
                    meterRegistry.counter("auth.failures", "type", "processing").increment();
                    log.error("❌ Authentication failed for IP: {} at {}: {}", clientIp, now, e.getMessage());
                    return respondWithUnauthorized(exchange);
                });
    }

    /* =========================
       Rate Limiting Methods
       ========================= */

    /**
     * Create IP-specific rate limiter based on path sensitivity
     */
    private Bucket createIpRateLimiter(String path) {
        int limit = isSensitivePath(path) ?
                rateLimitProperties.getIpSensitive() :
                rateLimitProperties.getIpStandard();

        return Bucket.builder()
                .addLimit(Bandwidth.classic(
                        limit,
                        Refill.intervally(
                                limit,
                                Duration.ofMinutes(rateLimitProperties.getWindowMinutes())
                        )
                ))
                .build();
    }

    /**
     * Get or create IP bucket with timestamp tracking
     */
    private Bucket getOrCreateIpBucket(String ip, String path, Instant now) {
        ipLastAccessMap.put(ip, now);
        return ipRateLimiters.computeIfAbsent(ip, k -> createIpRateLimiter(path));
    }

    /**
     * Cleanup old rate limiters (scheduled hourly)
     */
    private void cleanupOldRateLimiters() {
        Instant now = clock.instant();
        Instant threshold = now.minus(Duration.ofHours(24));

        ipLastAccessMap.entrySet().removeIf(entry -> {
            boolean shouldRemove = entry.getValue().isBefore(threshold);
            if (shouldRemove) {
                ipRateLimiters.remove(entry.getKey());
                log.debug("Removed stale rate limiter for IP: {}", entry.getKey());
            }
            return shouldRemove;
        });

        log.info("🧹 Rate limiter cleanup completed at {}. Active IPs: {}",
                now, ipRateLimiters.size());
    }

    /* =========================
       Response Methods
       ========================= */

    /**
     * Respond with 429 Too Many Requests
     */
    private Mono<Void> respondWithTooManyRequests(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        exchange.getResponse().getHeaders().set("X-RateLimit-Exceeded", clock.instant().toString());
        exchange.getResponse().getHeaders().set(
                "Retry-After",
                String.valueOf(rateLimitProperties.getWindowMinutes() * 60)
        );
        return exchange.getResponse().setComplete();
    }

    /**
     * Respond with 401 Unauthorized
     */
    private Mono<Void> respondWithUnauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().set("X-Auth-Failed", clock.instant().toString());
        exchange.getResponse().getHeaders().set("WWW-Authenticate", "Bearer");
        return exchange.getResponse().setComplete();
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Extract client IP address (supports X-Forwarded-For)
     */
    private String getClientIp(ServerHttpRequest request) {
        String xff = request.getHeaders().getFirst("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }

        if (request.getRemoteAddress() != null) {
            return request.getRemoteAddress().getAddress().getHostAddress();
        }

        return "unknown";
    }

    /**
     * Extract JWT token from Authorization header
     */
    private Mono<String> extractTokenFromRequest(ServerHttpRequest request) {
        return Mono.justOrEmpty(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(authHeader -> authHeader.startsWith("Bearer "))
                .map(authHeader -> authHeader.substring(7).trim())
                .filter(token -> !token.isEmpty());
    }

    /**
     * Check if path is public (supports exact and prefix matching)
     */
    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(publicPath -> {
            // Exact match
            if (path.equals(publicPath)) {
                return true;
            }
            // Prefix match (for paths ending with /)
            if (publicPath.endsWith("/") && path.startsWith(publicPath)) {
                return true;
            }
            return false;
        });
    }

    /**
     * Check if path is sensitive (requires stricter rate limiting)
     */
    private boolean isSensitivePath(String path) {
        return SENSITIVE_PATHS.stream().anyMatch(sensitivePath -> {
            // Exact match
            if (path.equals(sensitivePath)) {
                return true;
            }
            // Prefix match (for paths ending with /)
            if (sensitivePath.endsWith("/") && path.startsWith(sensitivePath)) {
                return true;
            }
            return false;
        });
    }
}