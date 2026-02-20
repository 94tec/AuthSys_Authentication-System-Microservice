package com.techStack.authSys.exception.email;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Email Sending Exception
 *
 * Thrown when email sending operations fail.
 * Can be treated as non-fatal in some scenarios (e.g., user created but email failed).
 *
 * Examples:
 * - SMTP server unavailable
 * - Invalid recipient email
 * - Email template rendering failure
 * - Rate limit exceeded
 */
public class EmailSendingException extends CustomException {
    private static final String DEFAULT_CODE = "EMAIL_SENDING_FAILED";

    public EmailSendingException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR,null, message, DEFAULT_CODE);
    }

    public EmailSendingException(String message, String errorCode) {
        super(HttpStatus.INTERNAL_SERVER_ERROR,null, message, errorCode);
    }

    public EmailSendingException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }

    /**
     * Factory: SMTP connection failed
     */
    public static EmailSendingException smtpConnectionFailed(String recipient, Throwable cause) {
        return new EmailSendingException(
                String.format("SMTP connection failed while sending to %s", recipient),
                cause
        );
    }

    /**
     * Factory: Template rendering failed
     */
    public static EmailSendingException templateRenderingFailed(String templateName, Throwable cause) {
        return new EmailSendingException(
                String.format("Failed to render email template: %s", templateName),
                cause
        );
    }

    /**
     * Factory: Rate limit exceeded
     */
    public static EmailSendingException rateLimitExceeded(String recipient) {
        return new EmailSendingException(
                String.format("Email rate limit exceeded for recipient: %s", recipient),
                "EMAIL_RATE_LIMIT_EXCEEDED"
        );
    }

    /**
     * Factory: Invalid recipient
     */
    public static EmailSendingException invalidRecipient(String recipient) {
        return new EmailSendingException(
                String.format("Invalid email recipient: %s", recipient),
                "INVALID_EMAIL_RECIPIENT"
        );
    }
}