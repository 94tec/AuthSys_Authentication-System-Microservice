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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.ConcurrentModificationException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Centralized error handling service for user registration
 * Translates technical exceptions into user-friendly error responses
 */
@Service
public class RegistrationErrorHandlerService {

    private static final Logger logger = LoggerFactory.getLogger(RegistrationErrorHandlerService.class);

    private static final Map<String, ErrorResponse> ERROR_MAPPING = new HashMap<>();

    //static {
    //    initializeErrorMappings();
    //}

    /**
     * Main method to handle registration errors and return appropriate user response
     */
    public Mono<ErrorResponse> handleRegistrationError(Throwable error, String email) {
        logger.debug("Handling registration error for email: {}", email);

        return Mono.fromCallable(() -> {
            ErrorResponse response = determineErrorResponse(error, email);
            //logError(error, email, response);
            return response;
        });
    }

    /**
     * Determine the appropriate error response based on exception type
     */
    private ErrorResponse determineErrorResponse(Throwable error, String email) {

        // 1. Email Already Exists (Most Common)
        if (error instanceof EmailAlreadyExistsException) {
            return new ErrorResponse(
                    HttpStatus.CONFLICT,
                    "EMAIL_ALREADY_EXISTS",
                    "This email address is already registered. Please sign in or use the 'Forgot Password' option.",
                    "email",
                    Map.of("action", "login_or_reset")
            );
        }

        // 2. Firebase Authentication Errors
        if (error instanceof FirebaseAuthException) {
            return handleFirebaseAuthError((FirebaseAuthException) error);
        }

        // 3. Validation Errors
        if (error instanceof ValidationException) {
            return handleValidationError((ValidationException) error);
        }

        // 4. Rate Limiting
        if (error instanceof RateLimitExceededException) {
            RateLimitExceededException rateLimitError = (RateLimitExceededException) error;
            return new ErrorResponse(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "RATE_LIMIT_EXCEEDED",
                    String.format("Too many registration attempts. Please try again in %d minutes.",
                            rateLimitError.getRetryAfterMinutes()),
                    null,
                    Map.of(
                            "retryAfter", rateLimitError.getRetryAfterMinutes(),
                            "reason", "security_protection"
                    )
            );
        }

        // 5. Suspicious Activity Detection
        if (error instanceof SuspiciousActivityException) {
            return new ErrorResponse(
                    HttpStatus.FORBIDDEN,
                    "SUSPICIOUS_ACTIVITY_DETECTED",
                    "We detected unusual activity. For security reasons, registration from your location is temporarily restricted. Please contact support.",
                    null,
                    Map.of("contactSupport", true)
            );
        }

        // 6. Geolocation/VPN Detection
        if (error instanceof GeolocationBlockedException) {
            return new ErrorResponse(
                    HttpStatus.FORBIDDEN,
                    "GEOLOCATION_RESTRICTED",
                    "Registration from your location is not currently supported. Please contact support if you believe this is an error.",
                    null,
                    Map.of("contactSupport", true)
            );
        }

        // 7. Domain Validation Errors
        if (error instanceof InvalidDomainException) {
            return new ErrorResponse(
                    HttpStatus.BAD_REQUEST,
                    "INVALID_EMAIL_DOMAIN",
                    "The email domain is not allowed for registration. Please use a valid email address.",
                    "email",
                    null
            );
        }

        if (error instanceof InactiveDomainException) {
            return new ErrorResponse(
                    HttpStatus.BAD_REQUEST,
                    "INACTIVE_EMAIL_DOMAIN",
                    "This email domain is temporarily not accepting new registrations. Please try a different email address.",
                    "email",
                    null
            );
        }

        // 8. Password Policy Violations
        if (error instanceof WeakPasswordException) {
            WeakPasswordException pwdError = (WeakPasswordException) error;
            return new ErrorResponse(
                    HttpStatus.BAD_REQUEST,
                    "WEAK_PASSWORD",
                    pwdError.getMessage(),
                    "password",
                    Map.of(
                            "requirements", pwdError.getPasswordRequirements(),
                            "violations", pwdError.getViolations()
                    )
            );
        }

        if (error instanceof CommonPasswordException) {
            return new ErrorResponse(
                    HttpStatus.BAD_REQUEST,
                    "COMMON_PASSWORD",
                    "This password is too common and easy to guess. Please choose a more unique password.",
                    "password",
                    null
            );
        }

        // 9. Network & Timeout Errors
        if (error instanceof TimeoutException) {
            return new ErrorResponse(
                    HttpStatus.REQUEST_TIMEOUT,
                    "REQUEST_TIMEOUT",
                    "Registration is taking longer than expected. Please try again in a moment.",
                    null,
                    Map.of("retryable", true)
            );
        }

        if (error instanceof java.net.ConnectException ||
                error instanceof java.net.UnknownHostException) {
            return new ErrorResponse(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "NETWORK_ERROR",
                    "Unable to connect to registration service. Please check your internet connection and try again.",
                    null,
                    Map.of("retryable", true)
            );
        }

        // 10. Service Unavailable
        if (error instanceof ServiceUnavailableException) {
            return new ErrorResponse(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "Our registration service is temporarily unavailable. Please try again in a few minutes.",
                    null,
                    Map.of(
                            "retryable", true,
                            "estimatedRetryTime", "5 minutes"
                    )
            );
        }

        // 11. Database/Firestore Errors
        if (error instanceof DatabaseException ||
                error.getMessage().contains("UNAVAILABLE") ||
                error.getMessage().contains("DEADLINE_EXCEEDED")) {
            return new ErrorResponse(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "DATABASE_ERROR",
                    "We're experiencing technical difficulties. Please try again shortly.",
                    null,
                    Map.of("retryable", true)
            );
        }

        // 12. Honeypot Triggered (Bot Detection)
        if (error instanceof BotDetectedException ||
                (error instanceof CustomException &&
                        error.getMessage().contains("Invalid form submission"))) {
            return new ErrorResponse(
                    HttpStatus.BAD_REQUEST,
                    "INVALID_SUBMISSION",
                    "Invalid form submission. Please refresh the page and try again.",
                    null,
                    Map.of("action", "refresh_page")
            );
        }

        // 13. Redis Cache Errors (Non-Critical)
        if (error instanceof CacheException) {
            logger.warn("Cache error during registration, proceeding without cache");
            return new ErrorResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "CACHE_ERROR",
                    "Registration is proceeding with reduced performance. Please be patient.",
                    null,
                    null
            );
        }

        // 14. Email Service Errors (Non-Blocking)
        if (error instanceof EmailServiceException) {
            return new ErrorResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "EMAIL_SERVICE_ERROR",
                    "Your account was created, but we couldn't send the verification email. You can request a new verification email from your account settings.",
                    null,
                    Map.of(
                            "accountCreated", true,
                            "action", "request_new_verification"
                    )
            );
        }

        // 15. Concurrent Registration Conflict
        if (error instanceof ConcurrentModificationException) {
            return new ErrorResponse(
                    HttpStatus.CONFLICT,
                    "CONCURRENT_REGISTRATION",
                    "Another registration is in progress with this email. Please wait a moment and try again.",
                    null,
                    Map.of("retryable", true)
            );
        }

        // 16. Invalid Input Format
        if (error instanceof IllegalArgumentException) {
            return new ErrorResponse(
                    HttpStatus.BAD_REQUEST,
                    "INVALID_INPUT",
                    "Invalid registration information provided. Please check your details and try again.",
                    null,
                    null
            );
        }

        // 17. Device Fingerprint Issues
        if (error instanceof DeviceFingerprintException) {
            return new ErrorResponse(
                    HttpStatus.BAD_REQUEST,
                    "DEVICE_VERIFICATION_FAILED",
                    "Unable to verify your device. Please ensure cookies and JavaScript are enabled.",
                    null,
                    Map.of("action", "enable_cookies_js")
            );
        }

        // 18. Permission/Authorization Issues
        if (error instanceof PermissionDeniedException) {
            return new ErrorResponse(
                    HttpStatus.FORBIDDEN,
                    "PERMISSION_DENIED",
                    "You don't have permission to register with the selected role. Please contact an administrator.",
                    null,
                    Map.of("contactSupport", true)
            );
        }

        // 19. Data Integrity Issues
        if (error instanceof DataIntegrityException) {
            return new ErrorResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "DATA_INTEGRITY_ERROR",
                    "A data consistency issue occurred. Our team has been notified. Please try again later.",
                    null,
                    Map.of("retryable", true)
            );
        }

        // 20. Generic CustomException (with HTTP status)
        if (error instanceof CustomException) {
            CustomException customError = (CustomException) error;
            return new ErrorResponse(
                    customError.getStatus(),
                    "REGISTRATION_ERROR",
                    customError.getMessage(),
                    null,
                    null
            );
        }

        // 21. Unknown/Unexpected Errors (Fallback)
        logger.error("Unexpected registration error", error);
        return new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "UNEXPECTED_ERROR",
                "An unexpected error occurred during registration. Please try again later or contact support if the problem persists.",
                null,
                Map.of(
                        "retryable", true,
                        "contactSupport", true
                )
        );
    }

    /**
     * Handle Firebase-specific authentication errors
     */
    private ErrorResponse handleFirebaseAuthError(FirebaseAuthException error) {
        String errorCode = String.valueOf(error.getErrorCode());

        switch (errorCode) {
            case "EMAIL_EXISTS":
                return new ErrorResponse(
                        HttpStatus.CONFLICT,
                        "EMAIL_ALREADY_EXISTS",
                        "This email address is already registered. Please sign in or reset your password.",
                        "email",
                        Map.of("action", "login_or_reset")
                );

            case "INVALID_EMAIL":
                return new ErrorResponse(
                        HttpStatus.BAD_REQUEST,
                        "INVALID_EMAIL_FORMAT",
                        "Please provide a valid email address.",
                        "email",
                        null
                );

            case "WEAK_PASSWORD":
                return new ErrorResponse(
                        HttpStatus.BAD_REQUEST,
                        "WEAK_PASSWORD",
                        "Password must be at least 6 characters long and include a mix of letters, numbers, and symbols.",
                        "password",
                        null
                );

            case "OPERATION_NOT_ALLOWED":
                return new ErrorResponse(
                        HttpStatus.FORBIDDEN,
                        "REGISTRATION_DISABLED",
                        "User registration is currently disabled. Please contact support.",
                        null,
                        Map.of("contactSupport", true)
                );

            case "TOO_MANY_ATTEMPTS_TRY_LATER":
                return new ErrorResponse(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "TOO_MANY_ATTEMPTS",
                        "Too many registration attempts. Please try again in 15 minutes.",
                        null,
                        Map.of("retryAfter", 15)
                );

            case "USER_DISABLED":
                return new ErrorResponse(
                        HttpStatus.FORBIDDEN,
                        "ACCOUNT_DISABLED",
                        "This account has been disabled. Please contact support for assistance.",
                        null,
                        Map.of("contactSupport", true)
                );

            case "CONFIGURATION_NOT_FOUND":
            case "INTERNAL_ERROR":
                return new ErrorResponse(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "FIREBASE_CONFIGURATION_ERROR",
                        "Authentication service is experiencing issues. Please try again later.",
                        null,
                        Map.of("retryable", true)
                );

            default:
                logger.warn("Unhandled Firebase error code: {}", errorCode);
                return new ErrorResponse(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "FIREBASE_ERROR",
                        "Authentication service error. Please try again or contact support.",
                        null,
                        Map.of("retryable", true, "contactSupport", true)
                );
        }
    }

    /**
     * Handle validation errors with field-specific messages
     */
    private ErrorResponse handleValidationError(ValidationException error) {
        return new ErrorResponse(
                HttpStatus.BAD_REQUEST,
                "VALIDATION_ERROR",
                error.getMessage(),
                error.getField(),
                error.getValidationErrors()
        );
    }

}

