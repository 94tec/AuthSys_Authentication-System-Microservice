package com.techStack.authSys.security;

import com.techStack.authSys.config.RateLimitProperties;
import com.techStack.authSys.service.FirebaseAuthenticationManager;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class FirebaseAuthFilter implements WebFilter {

    private final FirebaseAuthenticationManager firebaseAuthenticationManager;
    private final RateLimitProperties rateLimitProperties;

    private Bucket globalRateLimiter;
    // Configuration properties
    @Value("${security.rate-limit.global}")
    private int globalRateLimit;

    @Value("${security.rate-limit.ip-standard}")
    private int standardIpRateLimit;

    @Value("${security.rate-limit.ip-sensitive}")
    private int sensitiveIpRateLimit;

    @Value("${security.rate-limit.window-minutes}")
    private int rateLimitWindow;

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

    private final ServerSecurityContextRepository securityContextRepository;
    private final MeterRegistry meterRegistry;
    private final Map<String, Bucket> ipRateLimiters = new ConcurrentHashMap<>();
    private final Map<String, Long> ipLastAccessMap = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();

    // Initialize global rate limiter
    @PostConstruct
    public void init() {
        this.globalRateLimiter = Bucket.builder()
                .addLimit(Bandwidth.classic(
                        rateLimitProperties.getGlobal(),
                        Refill.intervally(rateLimitProperties.getGlobal(), Duration.ofMinutes(rateLimitProperties.getWindowMinutes()))
                ))
                .build();

        cleanupExecutor.scheduleAtFixedRate(this::cleanupOldRateLimiters, 1, 1, TimeUnit.HOURS);
        meterRegistry.gauge("auth.rate_limit.ips", ipRateLimiters, Map::size);
    }

    @PreDestroy
    public void shutdown() {
        cleanupExecutor.shutdown();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String clientIp = getClientIp(request);

        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        // Check global rate limit
        if (!globalRateLimiter.tryConsume(1)) {
            meterRegistry.counter("auth.rate_limit.global_hits").increment();
            log.warn("Global rate limit exceeded for IP: {}", clientIp);
            return respondWithTooManyRequests(exchange);
        }

        // Get or create IP-specific rate limiter
        Bucket ipBucket = getOrCreateIpBucket(clientIp, path);

        // Check IP-specific rate limit
        if (!ipBucket.tryConsume(1)) {
            meterRegistry.counter("auth.rate_limit.ip_hits", "ip", clientIp).increment();
            log.warn("Rate limit exceeded for IP: {} on path: {}", clientIp, path);
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
                    log.error("Authentication failed for IP: {}", clientIp, e);
                    return respondWithUnauthorized(exchange);
                });
    }

    private Bucket createIpRateLimiter(String path) {
        int limit = isSensitivePath(path) ? rateLimitProperties.getIpSensitive() : rateLimitProperties.getIpStandard();
        return Bucket.builder()
                .addLimit(Bandwidth.classic(limit,
                                Refill.intervally(limit, Duration.ofMinutes(rateLimitProperties.getWindowMinutes()))))
                        .build();
    }

    private Bucket getOrCreateIpBucket(String ip, String path) {
        ipLastAccessMap.put(ip, System.currentTimeMillis());
        return ipRateLimiters.computeIfAbsent(ip, k -> createIpRateLimiter(path));
    }

    private void cleanupOldRateLimiters() {
        long threshold = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(24);
        ipLastAccessMap.entrySet().removeIf(entry -> {
            boolean shouldRemove = entry.getValue() < threshold;
            if (shouldRemove) ipRateLimiters.remove(entry.getKey());
            return shouldRemove;
        });
        log.info("Rate limiter cleanup completed. Current entries: {}", ipRateLimiters.size());
    }

    private Mono<Void> respondWithTooManyRequests(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> respondWithUnauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private String getClientIp(ServerHttpRequest request) {
        String xff = request.getHeaders().getFirst("X-Forwarded-For");
        return (xff != null && !xff.isEmpty()) ?
                xff.split(",")[0].trim() :
                request.getRemoteAddress() != null ?
                        request.getRemoteAddress().getAddress().getHostAddress() :
                        "unknown";
    }

    private Mono<String> extractTokenFromRequest(ServerHttpRequest request) {
        return Mono.justOrEmpty(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(authHeader -> authHeader.startsWith("Bearer "))
                .map(authHeader -> authHeader.substring(7).trim());
                //.doOnNext(token -> log.info("🔐 Extracted token: {}", token));
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(publicPath ->
                path.equals(publicPath) ||
                        (publicPath.endsWith("/**") && path.startsWith(publicPath.substring(0, publicPath.length() - 3)))
        );
    }

    private boolean isSensitivePath(String path) {
        return SENSITIVE_PATHS.stream().anyMatch(sensitivePath ->
                path.equals(sensitivePath) ||
                        (sensitivePath.endsWith("/**") && path.startsWith(sensitivePath.substring(0, sensitivePath.length() - 3)))
        );
    }
}