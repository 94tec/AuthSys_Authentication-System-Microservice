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
            "/api/super-admin/register",
            "/api/super-admin/login",
            "/swagger-ui",
            "/v3/api-docs",
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/verify-email",
            "/api/register",
            "/api/otp",
            "/api/v1/password-reset/**"
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

        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        // Check global rate limit
        if (!globalRateLimiter.tryConsume(1)) {
            meterRegistry.counter("auth.rate_limit.global_hits").increment();
            log.warn("Global rate limit exceeded for IP: {} at {}", clientIp, now);
            return respondWithTooManyRequests(exchange);
        }

        // Get or create IP-specific rate limiter
        Bucket ipBucket = getOrCreateIpBucket(clientIp, path, now);

        // Check IP-specific rate limit
        if (!ipBucket.tryConsume(1)) {
            meterRegistry.counter("auth.rate_limit.ip_hits", "ip", clientIp).increment();
            log.warn("Rate limit exceeded for IP: {} on path: {} at {}", clientIp, path, now);
            return respondWithTooManyRequests(exchange);
        }

        return extractTokenFromRequest(request)
                .map(token -> new UsernamePasswordAuthenticationToken(token, token))
                .flatMap(firebaseAuthenticationManager::authenticate)
                .flatMap(auth -> securityContextRepository.save(exchange, new SecurityContextImpl(auth))
                        .then(chain.filter(exchange)))
                .switchIfEmpty(chain.filter(exchange))
                .onErrorResume(e -> {
                    meterRegistry.counter("auth.failures", "type", "processing").increment();
                    log.error("Authentication failed for IP: {} at {}", clientIp, now, e);
                    return respondWithUnauthorized(exchange);
                });
    }

    /* =========================
       Rate Limiting Methods
       ========================= */

    /**
     * Create IP-specific rate limiter
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
     * Cleanup old rate limiters (scheduled)
     */
    private void cleanupOldRateLimiters() {
        Instant now = clock.instant();
        Instant threshold = now.minus(Duration.ofHours(24));

        ipLastAccessMap.entrySet().removeIf(entry -> {
            boolean shouldRemove = entry.getValue().isBefore(threshold);
            if (shouldRemove) {
                ipRateLimiters.remove(entry.getKey());
            }
            return shouldRemove;
        });

        log.info("Rate limiter cleanup completed at {}. Current entries: {}",
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
        return exchange.getResponse().setComplete();
    }

    /**
     * Respond with 401 Unauthorized
     */
    private Mono<Void> respondWithUnauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().set("X-Auth-Failed", clock.instant().toString());
        return exchange.getResponse().setComplete();
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Extract client IP address
     */
    private String getClientIp(ServerHttpRequest request) {
        String xff = request.getHeaders().getFirst("X-Forwarded-For");
        return (xff != null && !xff.isEmpty()) ?
                xff.split(",")[0].trim() :
                request.getRemoteAddress() != null ?
                        request.getRemoteAddress().getAddress().getHostAddress() :
                        "unknown";
    }

    /**
     * Extract token from request
     */
    private Mono<String> extractTokenFromRequest(ServerHttpRequest request) {
        return Mono.justOrEmpty(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(authHeader -> authHeader.startsWith("Bearer "))
                .map(authHeader -> authHeader.substring(7).trim());
    }

    /**
     * Check if path is public
     */
    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(publicPath ->
                path.equals(publicPath) ||
                        (publicPath.endsWith("/**") &&
                                path.startsWith(publicPath.substring(0, publicPath.length() - 3)))
        );
    }

    /**
     * Check if path is sensitive
     */
    private boolean isSensitivePath(String path) {
        return SENSITIVE_PATHS.stream().anyMatch(sensitivePath ->
                path.equals(sensitivePath) ||
                        (sensitivePath.endsWith("/**") &&
                                path.startsWith(sensitivePath.substring(0, sensitivePath.length() - 3)))
        );
    }
}