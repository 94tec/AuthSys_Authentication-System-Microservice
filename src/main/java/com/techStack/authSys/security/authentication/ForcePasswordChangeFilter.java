package com.techStack.authSys.security.authentication;

import com.techStack.authSys.security.context.CustomUserDetails;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import java.net.URI;
import java.util.List;

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

    @NotNull
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        //logger.info("🚨 ForcePasswordChangeFilter triggered for path: {}", exchange.getRequest().getPath());
        String path = exchange.getRequest().getURI().getPath();
        logger.info("🔄 ForcePasswordChangeFilter processing path: {}", path);

        if (isAllowedPath(path)) {
            logger.info("✅ Path {} is allowed, skipping filter", path);
            return chain.filter(exchange);
        }

        return ReactiveSecurityContextHolder.getContext()
                .doOnNext(ctx -> logger.info("🔐 SecurityContext found, auth: {}", ctx.getAuthentication()))
                .map(SecurityContext::getAuthentication)
                .filter(auth -> {
                    boolean isAuthenticated = auth != null && auth.isAuthenticated();
                    logger.info("🔍 Authentication check - isAuthenticated: {}", isAuthenticated);
                    return isAuthenticated;
                })
                .cast(UsernamePasswordAuthenticationToken.class)
                .doOnNext(auth -> logger.info("👤 Principal type: {}", auth.getPrincipal().getClass().getName()))
                .flatMap(auth -> {
                    Object principal = auth.getPrincipal();
                    logger.info("🔎 Checking principal: {}", principal);

                    if (principal instanceof CustomUserDetails user) {
                        logger.info("👤 User: {}, forcePasswordChange: {}", user.getUsername(), user.isForcePasswordChange());
                        if (user.isForcePasswordChange()) {
                            logger.info("🚨 Redirecting user {} to password change", user.getUsername());
                            return handleForcePasswordChange(exchange, user);
                        }
                    } else {
                        logger.warn("⚠️ Principal is not CustomUserDetails: {}", principal.getClass());
                    }
                    return chain.filter(exchange);
                })
                .switchIfEmpty(Mono.defer(() -> {
                    logger.info("👻 No authentication found, allowing request");
                    return chain.filter(exchange);
                }));
    }

    private boolean isAllowedPath(String path) {
        return ALLOWED_PATHS.stream().anyMatch(allowed ->
                path.equals(allowed) || path.startsWith(allowed + "/")
        );
    }
    private Mono<Void> handleForcePasswordChange(ServerWebExchange exchange, CustomUserDetails user) {
        // For API requests, return 403 with custom header
        if (isApiRequest(exchange)) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FORBIDDEN);
            response.getHeaders().add("X-Force-Password-Change", "true");
            response.getHeaders().add("Location", "/change-password");
            return response.setComplete();
        }

        // For web requests, redirect to change password page
        return redirectToPasswordChange(exchange);
    }

    private boolean isApiRequest(ServerWebExchange exchange) {
        return exchange.getRequest().getPath().value().startsWith("/api/");
    }

    private Mono<Void> redirectToPasswordChange(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
        response.getHeaders().setLocation(URI.create("/change-password"));
        return response.setComplete();
    }
}
