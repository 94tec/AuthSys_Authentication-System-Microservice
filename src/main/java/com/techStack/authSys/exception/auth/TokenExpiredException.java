// exception/auth/TokenExpiredException.java
package com.techStack.authSys.exception.auth;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

import java.time.Instant;

/**
 * Thrown when a Firebase ID token has passed its expiry time.
 *
 * HTTP: 401  |  ErrorCode: TOKEN_EXPIRED
 *
 * Client action: attempt silent re-auth if refresh token available,
 * otherwise redirect to login.
 */
public class TokenExpiredException extends CustomException {

    private final String userId;
    private final Instant expiredAt;

    public TokenExpiredException(String message) {
        super(HttpStatus.UNAUTHORIZED, message);
        this.userId    = null;
        this.expiredAt = null;
    }

    public TokenExpiredException(String message, Throwable cause) {
        super(HttpStatus.UNAUTHORIZED, message, cause);
        this.userId    = null;
        this.expiredAt = null;
    }

    public TokenExpiredException(String message,
                                  String userId,
                                  Instant expiredAt) {
        super(HttpStatus.UNAUTHORIZED, message);
        this.userId    = userId;
        this.expiredAt = expiredAt;
    }

    public TokenExpiredException(String message,
                                  String userId,
                                  Instant expiredAt,
                                  Throwable cause) {
        super(HttpStatus.UNAUTHORIZED, message, cause);
        this.userId    = userId;
        this.expiredAt = expiredAt;
    }

    public String getUserId()     { return userId;    }
    public Instant getExpiredAt() { return expiredAt; }

    /* =========================
       Static Factory Methods
       ========================= */

    public static TokenExpiredException forUser(String userId, Instant expiredAt) {
        return new TokenExpiredException(
            String.format("Token expired for user %s at %s", userId, expiredAt),
            userId,
            expiredAt
        );
    }

    public static TokenExpiredException atTime(Instant expiredAt) {
        return new TokenExpiredException(
            "Token expired at " + expiredAt,
            null,
            expiredAt
        );
    }

    public static TokenExpiredException fromFirebase(Throwable cause) {
        return new TokenExpiredException(
            "Firebase token has expired: " + cause.getMessage(), cause);
    }

    public static TokenExpiredException generic() {
        return new TokenExpiredException("Authentication token has expired.");
    }
}