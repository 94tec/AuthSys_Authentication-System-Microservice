package com.techStack.authSys.auth.filter;

import com.techStack.authSys.config.security.RateLimitProperties;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
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
 * Rate Limiting Filter
 *
 * Applies global and per-IP request rate limits before authentication runs.
 * Authentication itself is handled solely by FirebaseSecurityContextRepository —
 * this filter no longer authenticates. It previously duplicated that work via
 * its own call to FirebaseAuthenticationManager.authenticate(), which raced
 * against FirebaseSecurityContextRepository.load() on every request: the two
 * independent authentication attempts could disagree (one succeeding, one
 * silently failing and falling back to anonymous), producing intermittent
 * AccessDeniedException on endpoints the user was actually authorized for.
 * That path is removed entirely — this filter now only gates on rate limits
 * and passes every request through to the rest of the chain.
 */
@Slf4j
//@Component
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
            "/api/password-reset/",

            "/api/auth/sso/handoff-code", // still needs auth — this is fine as-is
            "/api/auth/sso/redeem",

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

    private final RateLimitProperties rateLimitProperties;
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

        log.info("FirebaseAuthFilter (rate-limit only) initialized at {}", now);
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

        // ✅ Check if path is public - skip rate limiting entirely for these
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

        // Rate limits passed — hand off to the rest of the chain.
        // Authentication happens downstream, solely via FirebaseSecurityContextRepository.
        return chain.filter(exchange);
    }

    /* =========================
       Rate Limiting Methods
       ========================= */

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

    private Bucket getOrCreateIpBucket(String ip, String path, Instant now) {
        ipLastAccessMap.put(ip, now);
        return ipRateLimiters.computeIfAbsent(ip, k -> createIpRateLimiter(path));
    }

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

    private Mono<Void> respondWithTooManyRequests(ServerWebExchange exchange) {
        if (exchange.getResponse().isCommitted()) {
            log.warn("Response already committed — skipping 429 write at {}", clock.instant());
            return Mono.empty();
        }

        exchange.getResponse().getHeaders().set("X-RateLimit-Exceeded", clock.instant().toString());
        exchange.getResponse().getHeaders().set(
                "Retry-After",
                String.valueOf(rateLimitProperties.getWindowMinutes() * 60)
        );

        boolean statusSet = exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        if (!statusSet) {
            log.warn("Could not set 429 status — response likely already committed at {}", clock.instant());
            return Mono.empty();
        }

        return exchange.getResponse().setComplete();
    }

    /* =========================
       Utility Methods
       ========================= */

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

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(publicPath -> {
            if (path.equals(publicPath)) {
                return true;
            }
            if (publicPath.endsWith("/") && path.startsWith(publicPath)) {
                return true;
            }
            return false;
        });
    }

    private boolean isSensitivePath(String path) {
        return SENSITIVE_PATHS.stream().anyMatch(sensitivePath -> {
            if (path.equals(sensitivePath)) {
                return true;
            }
            if (sensitivePath.endsWith("/") && path.startsWith(sensitivePath)) {
                return true;
            }
            return false;
        });
    }
}