package com.techStack.authSys.util.auth;


import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.models.security.TokenType;
import com.techStack.authSys.service.token.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import static com.techStack.authSys.models.security.TokenType.ACCESS;
import static com.techStack.authSys.models.security.TokenType.TEMPORARY;

/**
 * Token Validation Utility
 *
 * Consolidates token validation logic used across multiple services
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenValidator {

    private final JwtService jwtService;

    /**
     * Validate temporary token and extract user ID
     * Used for first-time setup flow
     */
    public Mono<String> validateTemporaryToken(String token) {
        return Mono.fromCallable(() -> {
            if (token == null || token.isBlank()) {
                throw new AuthException("Token required", HttpStatus.BAD_REQUEST);
            }

            String jwt = extractJwt(token);
            String userId = jwtService.extractUserIdFromTemporaryToken(jwt);

            if (userId == null) {
                throw new AuthException(
                        "Invalid or expired temporary token",
                        HttpStatus.UNAUTHORIZED
                );
            }

            return userId;
        });
    }

    /**
     * Validate temporary login token and extract user ID
     * Used for login OTP flow
     */
    public Mono<String> validateTemporaryLoginToken(String token) {
        return Mono.fromCallable(() -> {
            if (token == null || !token.startsWith("Bearer ")) {
                throw new IllegalArgumentException("Invalid token format");
            }

            String jwt = token.substring(7);
            String userId = jwtService.extractUserIdFromTemporaryLoginToken(jwt);

            if (userId == null) {
                throw new IllegalArgumentException("Invalid or expired temporary token");
            }

            return userId;
        });
    }

    /**
     * Generic token validation with type check
     */
    public Mono<String> validateToken(String token, TokenType expectedType) {
        return Mono.fromCallable(() -> {
            if (token == null || token.isBlank()) {
                throw new AuthException("Token required", HttpStatus.BAD_REQUEST);
            }

            String jwt = extractJwt(token);
            String userId;

            switch (expectedType) {
                case TEMPORARY:
                    userId = jwtService.extractUserIdFromTemporaryToken(jwt);
                    break;
                case TEMPORARY_LOGIN:
                    userId = jwtService.extractUserIdFromTemporaryLoginToken(jwt);
                    break;
                case ACCESS:
                    userId = jwtService.getUserIdFromToken(jwt).block(); // Careful with block!
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported token type");
            }

            if (userId == null) {
                throw new AuthException(
                        "Invalid or expired " + expectedType.name().toLowerCase() + " token",
                        HttpStatus.UNAUTHORIZED
                );
            }

            return userId;
        });
    }

    /**
     * Extract JWT from Authorization header
     */
    private String extractJwt(String token) {
        return token.startsWith("Bearer ") ? token.substring(7) : token;
    }

}
