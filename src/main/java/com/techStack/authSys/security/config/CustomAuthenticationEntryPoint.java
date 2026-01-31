package com.techStack.authSys.security.config;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Custom Authentication Entry Point
 *
 * Handles authentication failures and unauthorized access.
 * Uses Clock for timestamp generation.
 */
@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationEntryPoint.class);
    private static final String REALM = "techStack";
    private static final String ERROR_TEMPLATE =
            "{\"timestamp\":\"%s\",\"status\":%d,\"error\":\"%s\",\"message\":\"%s\",\"path\":\"%s\"}";

    private final Clock clock;

    /* =========================
       Entry Point
       ========================= */

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        Instant now = clock.instant();
        String path = exchange.getRequest().getPath().toString();
        String method = exchange.getRequest().getMethod().name();
        String ip = getClientIp(exchange);

        logUnauthorizedAttempt(ip, method, path, ex, now);
        setSecurityHeaders(exchange, now);

        return createErrorResponse(exchange, path, ex, now);
    }

    /* =========================
       Logging
       ========================= */

    /**
     * Log unauthorized access attempt
     */
    private void logUnauthorizedAttempt(
            String ip,
            String method,
            String path,
            AuthenticationException ex,
            Instant timestamp
    ) {
        Map<String, String> details = new LinkedHashMap<>();
        details.put("event", "unauthorized_access");
        details.put("timestamp", timestamp.toString());
        details.put("ip", ip);
        details.put("method", method);
        details.put("path", path);
        details.put("error", ex.getMessage());

        logger.warn("Security event: {}", details);
    }

    /* =========================
       Response Building
       ========================= */

    /**
     * Set security headers
     */
    private void setSecurityHeaders(ServerWebExchange exchange, Instant timestamp) {
        HttpHeaders headers = exchange.getResponse().getHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("WWW-Authenticate", "Bearer realm=\"" + REALM + "\"");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("X-XSS-Protection", "1; mode=block");
        headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
        headers.set("Pragma", "no-cache");
        headers.set("Expires", "0");
        headers.set("Content-Security-Policy", "default-src 'self'");
        headers.set("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains");
        headers.set("X-Auth-Timestamp", timestamp.toString());
    }

    /**
     * Create error response
     */
    private Mono<Void> createErrorResponse(
            ServerWebExchange exchange,
            String path,
            AuthenticationException ex,
            Instant timestamp
    ) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);

        String errorMessage = getErrorMessage(ex);
        String jsonResponse = String.format(ERROR_TEMPLATE,
                timestamp,
                HttpStatus.UNAUTHORIZED.value(),
                "Unauthorized",
                errorMessage,
                path);

        return exchange.getResponse()
                .writeWith(Mono.just(exchange.getResponse()
                        .bufferFactory()
                        .wrap(jsonResponse.getBytes(StandardCharsets.UTF_8))));
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Get client IP address
     */
    private String getClientIp(ServerWebExchange exchange) {
        try {
            return exchange.getRequest().getRemoteAddress() != null ?
                    exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() :
                    "unknown";
        } catch (Exception e) {
            logger.warn("Could not determine client IP", e);
            return "unknown";
        }
    }

    /**
     * Get error message
     */
    private String getErrorMessage(AuthenticationException ex) {
        return ex.getMessage() != null ?
                sanitizeErrorMessage(ex.getMessage()) :
                "Authentication required";
    }

    /**
     * Sanitize error message to prevent XSS
     */
    private String sanitizeErrorMessage(String message) {
        return message.replace("\"", "'")
                .replace("\n", " ")
                .replace("\r", " ")
                .trim();
    }
}