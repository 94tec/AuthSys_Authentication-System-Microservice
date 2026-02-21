package com.techStack.authSys.util.auth;

import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.models.security.TokenType;
import com.techStack.authSys.service.token.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;

import static com.techStack.authSys.constants.SecurityConstants.*;

/**
 * Token Validation Utility
 *
 * Centralized, reactive-safe token validation across all auth flows.
 * Eliminates .block() usage, enforces consistent error handling,
 * and provides type-safe validation for all supported token types.
 *
 * <p>Handles:
 * <ul>
 *   <li>Temporary setup tokens (first-time password change + OTP)</li>
 *   <li>Temporary login tokens (MFA/OTP verification)</li>
 *   <li>Access tokens (standard API authentication)</li>
 *   <li>Refresh tokens (session renewal)</li>
 *   <li>Password reset tokens</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenValidator {

    private final JwtService jwtService;
    private final Clock clock;

    /* =========================
       Public Validation API
       ========================= */

    /**
     * Validate a temporary setup token and return the associated user ID.
     * Used in the first-time setup flow (password change + OTP).
     *
     * @param token raw token string (with or without "Bearer " prefix)
     * @return Mono emitting the userId, or error if invalid/expired
     */
    public Mono<String> validateTemporaryToken(String token) {
        return validateAndExtract(token, TokenType.TEMPORARY);
    }

    /**
     * Validate a temporary login token and return the associated user ID.
     * Used in MFA/OTP verification during the login flow.
     *
     * @param token raw token string (with or without "Bearer " prefix)
     * @return Mono emitting the userId, or error if invalid/expired
     */
    public Mono<String> validateTemporaryLoginToken(String token) {
        return validateAndExtract(token, TokenType.TEMPORARY_LOGIN);
    }

    /**
     * Validate an access token and return the associated user ID.
     *
     * @param token raw token string (with or without "Bearer " prefix)
     * @return Mono emitting the userId, or error if invalid/expired
     */
    public Mono<String> validateAccessToken(String token) {
        return validateAndExtract(token, TokenType.ACCESS);
    }

    /**
     * Validate a refresh token and return the associated user ID.
     *
     * @param token raw token string (with or without "Bearer " prefix)
     * @return Mono emitting the userId, or error if invalid/expired
     */
    public Mono<String> validateRefreshToken(String token) {
        return validateAndExtract(token, TokenType.REFRESH);
    }

    /**
     * Generic token validation dispatching on {@link TokenType}.
     * Fully reactive — no blocking calls.
     *
     * @param token        raw token string (with or without "Bearer " prefix)
     * @param expectedType the expected {@link TokenType}
     * @return Mono emitting the userId, or error if token is invalid/expired/wrong type
     */
    public Mono<String> validateToken(String token, TokenType expectedType) {
        return validateAndExtract(token, expectedType);
    }

    /**
     * Validate a token and return the full {@link Claims} object.
     * Useful when callers need more than just the userId.
     *
     * @param token        raw token string (with or without "Bearer " prefix)
     * @param expectedType the expected {@link TokenType}
     * @return Mono emitting the Claims, or error if invalid
     */
    public Mono<Claims> validateAndGetClaims(String token, TokenType expectedType) {
        return Mono.fromCallable(() -> extractJwt(token, expectedType))
                .flatMap(jwt -> resolveClaimsReactive(jwt, expectedType))
                .doOnSuccess(claims -> logValidationSuccess(expectedType, claims.getSubject()))
                .doOnError(e -> logValidationFailure(expectedType, token, e))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       Core Validation Logic
       ========================= */

    /**
     * Central validation pipeline shared by all public methods.
     */
    private Mono<String> validateAndExtract(String token, TokenType expectedType) {
        return Mono.fromCallable(() -> extractJwt(token, expectedType))
                .flatMap(jwt -> resolveUserIdReactive(jwt, expectedType))
                .doOnSuccess(userId -> logValidationSuccess(expectedType, userId))
                .doOnError(e -> logValidationFailure(expectedType, safeFingerprint(token), e))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Strips the "Bearer " prefix and validates the raw token string is present.
     * Throws immediately (synchronously) so errors surface in fromCallable cleanly.
     */
    private String extractJwt(String token, TokenType expectedType) {
        if (StringUtils.isBlank(token)) {
            throw new AuthException(
                    expectedType.name().toLowerCase() + " token is required",
                    HttpStatus.BAD_REQUEST
            );
        }
        return token.startsWith("Bearer ") ? token.substring(7) : token;
    }

    /**
     * Resolves the user ID reactively based on the token type.
     * No .block() usage — each branch returns a Mono.
     */
    private Mono<String> resolveUserIdReactive(String jwt, TokenType expectedType) {
        return switch (expectedType) {
            case TEMPORARY -> Mono.fromCallable(() ->
                            jwtService.extractUserIdFromTemporaryToken(jwt))
                    .flatMap(userId -> requireNonNullUserId(userId, expectedType));

            case TEMPORARY_LOGIN -> Mono.fromCallable(() ->
                            jwtService.extractUserIdFromTemporaryLoginToken(jwt))
                    .flatMap(userId -> requireNonNullUserId(userId, expectedType));

            case ACCESS -> jwtService.getUserIdFromToken(jwt)
                    .flatMap(userId -> requireNonNullUserId(userId, expectedType));

            case REFRESH -> jwtService.validateRefreshToken(jwt)
                    .map(Claims::getSubject)
                    .flatMap(userId -> requireNonNullUserId(userId, expectedType));

            case PASSWORD_RESET -> jwtService.validateToken(jwt, CLAIM_TYPE_PASSWORD_RESET)
                    .map(Claims::getSubject)
                    .flatMap(userId -> requireNonNullUserId(userId, expectedType));

            case CUSTOM_JWT, FIREBASE -> Mono.error(new AuthException(
                    "Direct validation of " + expectedType.name() + " tokens is not supported here",
                    HttpStatus.BAD_REQUEST
            ));

            default -> Mono.error(new AuthException(
                    "Unsupported token type: " + expectedType.name(),
                    HttpStatus.BAD_REQUEST
            ));
        };
    }

    /**
     * Resolves the full Claims object reactively based on the token type.
     */
    private Mono<Claims> resolveClaimsReactive(String jwt, TokenType expectedType) {
        return switch (expectedType) {
            case ACCESS -> jwtService.validateToken(jwt, CLAIM_TYPE_ACCESS);
            case REFRESH -> jwtService.validateRefreshToken(jwt);
            case PASSWORD_RESET -> jwtService.validateToken(jwt, CLAIM_TYPE_PASSWORD_RESET);
            case TEMPORARY -> jwtService.validateToken(jwt, CLAIM_TYPE_TEMPORARY);
            case TEMPORARY_LOGIN -> jwtService.validateToken(jwt, TOKEN_TYPE_TEMPORARY_LOGIN);
            default -> Mono.error(new AuthException(
                    "Claims extraction not supported for type: " + expectedType.name(),
                    HttpStatus.BAD_REQUEST
            ));
        };
    }

    /**
     * Ensures a userId extracted from synchronous methods is non-null,
     * converting null into a typed AuthException.
     */
    private Mono<String> requireNonNullUserId(String userId, TokenType expectedType) {
        if (StringUtils.isBlank(userId)) {
            return Mono.error(new AuthException(
                    "Invalid or expired " + expectedType.name().toLowerCase() + " token",
                    HttpStatus.UNAUTHORIZED
            ));
        }
        return Mono.just(userId);
    }

    /* =========================
       Bearer Token Utilities
       ========================= */

    /**
     * Returns true if the token string includes a valid "Bearer " prefix.
     */
    public boolean hasBearerPrefix(String token) {
        return StringUtils.isNotBlank(token) && token.startsWith("Bearer ");
    }

    /**
     * Strips the Bearer prefix if present, or returns the token as-is.
     */
    public String stripBearerPrefix(String token) {
        if (StringUtils.isBlank(token)) return token;
        return token.startsWith("Bearer ") ? token.substring(7) : token;
    }

    /* =========================
       Logging
       ========================= */

    private void logValidationSuccess(TokenType type, String userId) {
        log.debug("Token validation succeeded [type={}, userId={}] at {}",
                type, userId, clock.instant());
    }

    private void logValidationFailure(TokenType type, String tokenFingerprint, Throwable e) {
        log.warn("Token validation failed [type={}, token={}, error={}] at {}",
                type, tokenFingerprint, e.getMessage(), clock.instant());
    }

    /**
     * Produces a safe non-sensitive fingerprint from a raw token string for logging.
     */
    private String safeFingerprint(String token) {
        if (StringUtils.isBlank(token)) return "<empty>";
        String stripped = stripBearerPrefix(token);
        int len = stripped.length();
        if (len <= 10) return "***";
        return stripped.substring(0, 5) + "..." + stripped.substring(len - 5);
    }
}