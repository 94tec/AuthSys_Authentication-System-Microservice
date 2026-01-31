package com.techStack.authSys.security.authentication;

import com.techStack.authSys.security.context.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

/**
 * Force Password Change Filter
 *
 * Enforces password change requirements for users.
 * Uses Clock for all timestamp operations.
 */
@Component
@RequiredArgsConstructor
public class ForcePasswordChangeFilter implements WebFilter {

    private static final Logger logger = LoggerFactory.getLogger(ForcePasswordChangeFilter.class);

    private static final List<String> ALLOWED_PATHS = List.of(
            "/change-password",
            "/api/auth/change-password",
            "/api/auth/logout",
            "/login",
            "/logout",
            "/favicon.ico",
            "/actuator/health",
            "/static/**",
            "/css/**",
            "/js/**",
            "/images/**"
    );

    private final Clock clock;

    /* =========================
       Filter Implementation
       ========================= */

    @NotNull
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        Instant now = clock.instant();

        logger.debug("ForcePasswordChangeFilter processing path: {} at {}", path, now);

        if (isAllowedPath(path)) {
            logger.debug("Path {} is allowed, skipping filter", path);
            return chain.filter(exchange);
        }

        return ReactiveSecurityContextHolder.getContext()
                .doOnNext(ctx -> logger.debug("SecurityContext found at {}, auth: {}",
                        now, ctx.getAuthentication()))
                .map(SecurityContext::getAuthentication)
                .filter(auth -> {
                    boolean isAuthenticated = auth != null && auth.isAuthenticated();
                    logger.debug("Authentication check at {} - isAuthenticated: {}",
                            now, isAuthenticated);
                    return isAuthenticated;
                })
                .cast(UsernamePasswordAuthenticationToken.class)
                .doOnNext(auth -> logger.debug("Principal type: {} at {}",
                        auth.getPrincipal().getClass().getName(), now))
                .flatMap(auth -> {
                    Object principal = auth.getPrincipal();

                    if (principal instanceof CustomUserDetails user) {
                        logger.debug("User: {}, forcePasswordChange: {} at {}",
                                user.getUsername(), user.isForcePasswordChange(), now);

                        if (user.isForcePasswordChange()) {
                            logger.info("Redirecting user {} to password change at {}",
                                    user.getUsername(), now);
                            return handleForcePasswordChange(exchange, user, now);
                        }
                    } else {
                        logger.warn("Principal is not CustomUserDetails: {} at {}",
                                principal.getClass(), now);
                    }

                    return chain.filter(exchange);
                })
                .switchIfEmpty(Mono.defer(() -> {
                    logger.debug("No authentication found at {}, allowing request", now);
                    return chain.filter(exchange);
                }));
    }

    /* =========================
       Password Change Handling
       ========================= */

    /**
     * Handle force password change
     */
    private Mono<Void> handleForcePasswordChange(
            ServerWebExchange exchange,
            CustomUserDetails user,
            Instant now
    ) {
        // For API requests, return 403 with custom header
        if (isApiRequest(exchange)) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FORBIDDEN);
            response.getHeaders().add("X-Force-Password-Change", "true");
            response.getHeaders().add("X-Timestamp", now.toString());
            response.getHeaders().add("Location", "/change-password");

            logger.warn("Blocked API request from {} requiring password change at {}",
                    user.getUsername(), now);

            return response.setComplete();
        }

        // For web requests, redirect to change password page
        logger.info("Redirecting web request from {} to password change at {}",
                user.getUsername(), now);

        return redirectToPasswordChange(exchange, now);
    }

    /**
     * Check if request is API request
     */
    private boolean isApiRequest(ServerWebExchange exchange) {
        return exchange.getRequest().getPath().value().startsWith("/api/");
    }

    /**
     * Redirect to password change page
     */
    private Mono<Void> redirectToPasswordChange(ServerWebExchange exchange, Instant now) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
        response.getHeaders().setLocation(URI.create("/change-password"));
        response.getHeaders().add("X-Redirect-Timestamp", now.toString());
        return response.setComplete();
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Check if path is allowed
     */
    private boolean isAllowedPath(String path) {
        return ALLOWED_PATHS.stream().anyMatch(allowed ->
                path.equals(allowed) || path.startsWith(allowed + "/")
        );
    }
}