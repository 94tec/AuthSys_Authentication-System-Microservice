package com.techStack.authSys.service.registration;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.dto.response.ErrorResponse;
import com.techStack.authSys.exception.authorization.PermissionDeniedException;
import com.techStack.authSys.exception.data.CacheException;
import com.techStack.authSys.exception.data.DataIntegrityException;
import com.techStack.authSys.exception.data.DatabaseException;
import com.techStack.authSys.exception.domain.InactiveDomainException;
import com.techStack.authSys.exception.domain.InvalidDomainException;
import com.techStack.authSys.exception.email.EmailAlreadyExistsException;
import com.techStack.authSys.exception.email.EmailServiceException;
import com.techStack.authSys.exception.password.CommonPasswordException;
import com.techStack.authSys.exception.password.WeakPasswordException;
import com.techStack.authSys.exception.security.*;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.exception.service.ServiceUnavailableException;
import com.techStack.authSys.exception.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Registration Error Handler Service
 *
 * Centralized error handling for user registration.
 * Translates technical exceptions into user-friendly error responses.
 */
@Service
@RequiredArgsConstructor
public class RegistrationErrorHandlerService {

    private static final Logger logger = LoggerFactory.getLogger(RegistrationErrorHandlerService.class);

    private final Clock clock;

    /**
     * Main method to handle registration errors
     */
    public Mono<ErrorResponse> handleRegistrationError(Throwable error, String email) {
        logger.debug("Handling registration error for email: {}", email);

        return Mono.fromCallable(() -> {
            ErrorResponse response = determineErrorResponse(error, email);
            logError(error, email, response);
            return response;
        });
    }

    /**
     * Determine appropriate error response based on exception type
     */
    private ErrorResponse determineErrorResponse(Throwable error, String email) {
        Instant now = clock.instant();

        // 1. Email Already Exists (Most Common)
        if (error instanceof EmailAlreadyExistsException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.CONFLICT)
                    .errorCode("EMAIL_ALREADY_EXISTS")
                    .message("This email address is already registered. Please sign in or use the 'Forgot Password' option.")
                    .field("email")
                    .details(Map.of("action", "login_or_reset"))
                    .timestamp(now)
                    .build();
        }

        // 2. Firebase Authentication Errors
        if (error instanceof FirebaseAuthException) {
            return handleFirebaseAuthError((FirebaseAuthException) error, now);
        }

        // 3. Validation Errors
        if (error instanceof ValidationException) {
            return handleValidationError((ValidationException) error, now);
        }

        // 4. Rate Limiting
        if (error instanceof RateLimitExceededException rateLimitError) {
            return ErrorResponse.builder()
                    .status(HttpStatus.TOO_MANY_REQUESTS)
                    .errorCode("RATE_LIMIT_EXCEEDED")
                    .message(String.format("Too many registration attempts. Please try again in %d minutes.",
                            rateLimitError.getRetryAfterMinutes()))
                    .details(Map.of(
                            "retryAfter", rateLimitError.getRetryAfterMinutes(),
                            "reason", "security_protection"
                    ))
                    .timestamp(now)
                    .build();
        }

        // 5. Suspicious Activity Detection
        if (error instanceof SuspiciousActivityException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.FORBIDDEN)
                    .errorCode("SUSPICIOUS_ACTIVITY_DETECTED")
                    .message("We detected unusual activity. For security reasons, registration from your location is temporarily restricted.")
                    .details(Map.of("contactSupport", true))
                    .timestamp(now)
                    .build();
        }

        // 6. Password Policy Violations
        if (error instanceof WeakPasswordException pwdError) {
            return ErrorResponse.builder()
                    .status(HttpStatus.BAD_REQUEST)
                    .errorCode("WEAK_PASSWORD")
                    .message(pwdError.getMessage())
                    .field("password")
                    .details(Map.of(
                            "requirements", pwdError.getPasswordRequirements(),
                            "violations", pwdError.getViolations()
                    ))
                    .timestamp(now)
                    .build();
        }

        // 7. Service Unavailable
        if (error instanceof ServiceUnavailableException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .errorCode("SERVICE_UNAVAILABLE")
                    .message("Our registration service is temporarily unavailable. Please try again in a few minutes.")
                    .details(Map.of(
                            "retryable", true,
                            "estimatedRetryTime", "5 minutes"
                    ))
                    .timestamp(now)
                    .build();
        }

        // 8. Unknown/Unexpected Errors (Fallback)
        logger.error("Unexpected registration error", error);
        return ErrorResponse.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .errorCode("UNEXPECTED_ERROR")
                .message("An unexpected error occurred during registration. Please try again later or contact support.")
                .details(Map.of(
                        "retryable", true,
                        "contactSupport", true
                ))
                .timestamp(now)
                .build();
    }

    /**
     * Handle Firebase-specific authentication errors
     */
    private ErrorResponse handleFirebaseAuthError(FirebaseAuthException error, Instant timestamp) {
        String errorCode = String.valueOf(error.getErrorCode());

        return switch (errorCode) {
            case "EMAIL_EXISTS" -> ErrorResponse.builder()
                    .status(HttpStatus.CONFLICT)
                    .errorCode("EMAIL_ALREADY_EXISTS")
                    .message("This email address is already registered.")
                    .field("email")
                    .details(Map.of("action", "login_or_reset"))
                    .timestamp(timestamp)
                    .build();

            case "WEAK_PASSWORD" -> ErrorResponse.builder()
                    .status(HttpStatus.BAD_REQUEST)
                    .errorCode("WEAK_PASSWORD")
                    .message("Password must be at least 6 characters long.")
                    .field("password")
                    .timestamp(timestamp)
                    .build();

            default -> ErrorResponse.builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .errorCode("FIREBASE_ERROR")
                    .message("Authentication service error. Please try again.")
                    .details(Map.of("retryable", true))
                    .timestamp(timestamp)
                    .build();
        };
    }

    /**
     * Handle validation errors
     */
    private ErrorResponse handleValidationError(ValidationException error, Instant timestamp) {
        return ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST)
                .errorCode("VALIDATION_ERROR")
                .message(error.getMessage())
                .field(error.getField())
                .details(error.getValidationErrors())
                .timestamp(timestamp)
                .build();
    }

    /**
     * Log error details
     */
    private void logError(Throwable error, String email, ErrorResponse response) {
        logger.error("Registration error for {}: {} - Response: {}",
                email,
                error.getMessage(),
                response.getErrorCode());
    }
}