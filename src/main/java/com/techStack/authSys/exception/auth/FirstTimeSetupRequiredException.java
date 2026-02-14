package com.techStack.authSys.exception.auth;


import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when first-time setup is required.
 * Contains temporary token for password change flow.
 */
@Getter
public class FirstTimeSetupRequiredException extends AuthException {
    private final String userId;
    private final String temporaryToken;

    public FirstTimeSetupRequiredException(String userId, String temporaryToken, String message) {
        super(message, HttpStatus.FORBIDDEN);
        this.userId = userId;
        this.temporaryToken = temporaryToken;
    }
}
