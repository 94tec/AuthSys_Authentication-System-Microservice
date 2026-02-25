package com.techStack.authSys.exception.auth;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Thrown when a token is present but cannot be trusted.
 * Covers: malformed JWT, bad signature, wrong issuer, revoked token.
 *
 * HTTP: 401  |  ErrorCode: INVALID_TOKEN
 *
 * Distinct from TokenExpiredException:
 *   InvalidTokenException  → token is structurally invalid or revoked.
 *                            Client must force logout + redirect to login.
 *   TokenExpiredException  → token was valid but exp claim is in the past.
 *                            Client can attempt silent re-auth first.
 */
public class InvalidTokenException extends CustomException {

    public InvalidTokenException(String message) {
        super(HttpStatus.UNAUTHORIZED, message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(HttpStatus.UNAUTHORIZED, message, cause);
    }

    /* =========================
       Static Factory Methods
       ========================= */

    public static InvalidTokenException malformed() {
        return new InvalidTokenException("Token is malformed and cannot be parsed.");
    }

    public static InvalidTokenException revoked(String userId) {
        return new InvalidTokenException(
                "Token has been revoked for user: " + userId);
    }

    public static InvalidTokenException missing() {
        return new InvalidTokenException(
                "Authorization token is missing or blank.");
    }

    public static InvalidTokenException wrongIssuer(String actualIssuer) {
        return new InvalidTokenException(
                "Token issuer '" + actualIssuer + "' is not trusted.");
    }

    public static InvalidTokenException fromFirebase(Throwable cause) {
        return new InvalidTokenException(
                "Firebase token is invalid: " + cause.getMessage(), cause);
    }
}