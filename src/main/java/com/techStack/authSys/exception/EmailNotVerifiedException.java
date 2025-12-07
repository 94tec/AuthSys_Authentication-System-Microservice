
package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class EmailNotVerifiedException extends CustomException {
    public EmailNotVerifiedException(String message) {
        super(HttpStatus.UNAUTHORIZED, message);
    }

    public EmailNotVerifiedException(HttpStatus status, String message) {
        super(status, message);
    }

    public EmailNotVerifiedException(HttpStatus status, String message, Throwable cause) {
        super(status, message, cause);
    }

    public EmailNotVerifiedException(HttpStatus status, String message, String field, String code) {
        super(status, message, field, code);
    }

    public EmailNotVerifiedException(HttpStatus status, String message, Throwable cause, String field, String code) {
        super(status, message, cause, field, code);
    }

    public static AuthException EmailNotVerifiedException() {
        return new AuthException(
                "Email not verified. Please check your inbox for verification link.",
                HttpStatus.FORBIDDEN,
                "AUTH_004"
        );
    }
}
