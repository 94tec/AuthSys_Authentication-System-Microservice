package com.techStack.authSys.exception.auth;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when OTP verification is required.
 * Contains temporary token for OTP verification flow.
 */
@Getter
public class OtpVerificationRequiredException extends AuthException {
    private final String userId;
    private final String temporaryToken;

    public OtpVerificationRequiredException(String userId, String temporaryToken, String message) {
        super(message, HttpStatus.FORBIDDEN);
        this.userId = userId;
        this.temporaryToken = temporaryToken;
    }
}