package com.techStack.authSys.security.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.techStack.authSys.service.token.TokenProcessingService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements ServerAccessDeniedHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAccessDeniedHandler.class);
    private final TokenProcessingService tokenProcessingService;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException ex) {
        String token = extractToken(exchange);

        return Mono.justOrEmpty(token)
                .flatMap(tokenProcessingService::processToken)
                .defaultIfEmpty(createAnonymousResult())
                .flatMap(result -> {
                    logAccessDenied(result, exchange);
                    return createErrorResponse(exchange, result);
                });
    }

    private TokenProcessingService.TokenProcessingResult createAnonymousResult() {
        return new TokenProcessingService.TokenProcessingResult(
                "Anonymous",
                "N/A",
                null,
                Map.of(),
                List.of()
        );
    }
    private void logAccessDenied(TokenProcessingService.TokenProcessingResult result, ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().toString();
        String method = exchange.getRequest().getMethod().name();
        String ip = exchange.getRequest().getRemoteAddress() != null ?
                exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() : "unknown";

        logger.warn("Access denied: UserID={}, Email={}, Method={}, Path={}, IP={}",
                result.userId(), result.email(), method, path, ip);
    }
    private Mono<Void> createErrorResponse(ServerWebExchange exchange, TokenProcessingService.TokenProcessingResult result) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> response = Map.of(
                "timestamp", Instant.now().toString(),
                "status", HttpStatus.FORBIDDEN.value(),
                "error", "Forbidden",
                "message", "You do not have permission to access this resource",
                "path", exchange.getRequest().getPath().toString(),
                "userId", result.userId(),
                "email", result.email(),
                "tokenType", result.tokenType() != null ? ((TokenProcessingService.TokenType) result.tokenType()).name() : "NONE"


        );

        return exchange.getResponse().writeWith(Mono.just(
                exchange.getResponse().bufferFactory().wrap(toJson(response))
        ));
    }

    private byte[] toJson(Map<String, Object> data) {
        try {
            return new ObjectMapper().writeValueAsBytes(data);
        } catch (JsonProcessingException e) {
            return "{\"error\":\"Failed to generate error response\"}".getBytes(StandardCharsets.UTF_8);
        }
    }
    private String extractToken(ServerWebExchange exchange) {
        String header = exchange.getRequest().getHeaders().getFirst("Authorization");
        return (header != null && header.startsWith("Bearer ")) ? header.substring(7) : null;
    }

}
