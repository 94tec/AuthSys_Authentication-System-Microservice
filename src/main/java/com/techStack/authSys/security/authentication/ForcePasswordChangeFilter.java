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
 * Enforces password change for users with forcePasswordChange=true.
 * Phone/OTP verification is enforced once, at login time, by
 * AuthenticationOrchestrator — NOT repeated here on every request.
 *
 * Uses Clock for all timestamp operations.
 */
@Component
@RequiredArgsConstructor
public class ForcePasswordChangeFilter implements WebFilter {

    private static final Logger logger = LoggerFactory.getLogger(ForcePasswordChangeFilter.class);

    private static final List<String> ALLOWED_PATHS = List.of(

            // Super Admin bootstrap
            "/api/super-admin/register",
            "/api/super-admin/login",
            // Password change endpoints
            "/api/auth/change-password",
            "/api/auth/first-time-setup/",

            // Swagger UI
            "/swagger-ui.html",
            "/swagger-ui/",
            "/v3/api-docs",
            "/webjars/",

            // Authentication
            "/api/auth/login",
            "/api/auth/logout",
            "/api/auth/verify-email",
            "/api/auth/resend-verification",

            // Static resources
            "/favicon.ico",
            "/static/",
            "/css/",
            "/js/",
            "/images/",

            // Health checks
            "/actuator/",
            "/health/"
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
                                user.getUsername(),
                                user.isForcePasswordChange(),
                                now);

                        // Phone/OTP verification is enforced once at login by
                        // AuthenticationOrchestrator. Only password-change is
                        // re-checked on every request here, since a user can
                        // keep using an already-issued access token across
                        // multiple requests before they change their password.
                        if (user.isForcePasswordChange()) {
                            return handleIncompleteSetup(exchange, user, now);
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
       Setup Handling
       ========================= */

    /**
     * Handle incomplete setup (password change pending).
     *
     * IMPORTANT: all header mutations happen BEFORE setStatusCode/setComplete
     * triggers the response to commit. Mutating headers after commit throws
     * UnsupportedOperationException on ReadOnlyHttpHeaders, which is what was
     * causing the cascading "response already committed" crashes.
     */
    private Mono<Void> handleIncompleteSetup(
            ServerWebExchange exchange,
            CustomUserDetails user,
            Instant now
    ) {
        String setupStatus = "PASSWORD_CHANGE_REQUIRED";

        if (isApiRequest(exchange)) {
            ServerHttpResponse response = exchange.getResponse();

            if (response.isCommitted()) {
                logger.warn("Response already committed for {} — skipping header mutation at {}",
                        user.getUsername(), now);
                return Mono.empty();
            }

            response.getHeaders().add("X-Setup-Required", "true");
            response.getHeaders().add("X-Setup-Status", setupStatus);
            response.getHeaders().add("X-Force-Password-Change",
                    String.valueOf(user.isForcePasswordChange()));
            response.getHeaders().add("X-Timestamp", now.toString());
            response.getHeaders().add("Location", "/api/auth/first-time-setup/change-password");

            boolean statusSet = response.setStatusCode(HttpStatus.FORBIDDEN);
            if (!statusSet) {
                logger.warn("Could not set status code for {} — response likely already committed at {}",
                        user.getUsername(), now);
                return Mono.empty();
            }

            logger.warn("Blocked API request from {} requiring setup ({}) at {}",
                    user.getUsername(), setupStatus, now);

            return response.setComplete();
        }

        logger.info("Redirecting web request from {} to setup ({}) at {}",
                user.getUsername(), setupStatus, now);

        return redirectToSetup(exchange, now);
    }

    /**
     * Check if request is API request
     */
    private boolean isApiRequest(ServerWebExchange exchange) {
        return exchange.getRequest().getPath().value().startsWith("/api/");
    }

    /**
     * Redirect to setup page
     */
    private Mono<Void> redirectToSetup(ServerWebExchange exchange, Instant now) {
        ServerHttpResponse response = exchange.getResponse();

        if (response.isCommitted()) {
            logger.warn("Response already committed — skipping redirect at {}", now);
            return Mono.empty();
        }

        response.getHeaders().setLocation(URI.create("/first-time-setup"));
        response.getHeaders().add("X-Redirect-Timestamp", now.toString());

        boolean statusSet = response.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
        if (!statusSet) {
            logger.warn("Could not set redirect status code — response likely already committed at {}", now);
            return Mono.empty();
        }

        return response.setComplete();
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Check if path is allowed
     */
    private boolean isAllowedPath(String path) {
        return ALLOWED_PATHS.stream().anyMatch(allowed -> {
            if (allowed.endsWith("/**")) {
                String prefix = allowed.substring(0, allowed.length() - 3);
                return path.startsWith(prefix);
            }
            return path.equals(allowed) || path.startsWith(allowed + "/");
        });
    }
}