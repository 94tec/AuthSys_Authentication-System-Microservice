package com.techStack.authSys.service.auth;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.dto.response.ErrorResponse;
import com.techStack.authSys.exception.account.AccountDisabledException;
import com.techStack.authSys.exception.account.AccountLockedException;
import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.exception.auth.InvalidTokenException;
import com.techStack.authSys.exception.auth.TransientAuthenticationException;
import com.techStack.authSys.exception.data.DatabaseException;
import com.techStack.authSys.exception.data.NetworkException;
import com.techStack.authSys.exception.email.EmailNotVerifiedException;
import com.techStack.authSys.exception.password.PasswordExpiredException;
import com.techStack.authSys.exception.security.RateLimitExceededException;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.exception.service.ServiceUnavailableException;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Centralized error handling service for authentication operations.
 * Translates technical exceptions into user-friendly error responses.
 */
@Slf4j
@Service
public class AuthenticationErrorHandlerService {

    /**
     * Main method to handle authentication errors and return appropriate user response.
     */
    public Mono<ErrorResponse> handleAuthenticationError(Throwable error, String email) {
        log.debug("Handling authentication error for email: {}", HelperUtils.maskEmail(email));

        return Mono.fromCallable(() -> {
            ErrorResponse response = determineErrorResponse(error, email);
            logError(error, email, response);
            return response;
        });
    }

    /**
     * Determine the appropriate error response based on exception type.
     */
    private ErrorResponse determineErrorResponse(Throwable error, String email) {

        // 1. Invalid Credentials (Most Common)
        if (error instanceof AuthException) {
            return handleAuthException((AuthException) error);
        }

        // 2. Account Status Issues
        if (error instanceof AccountLockedException) {
            AccountLockedException lockedException = (AccountLockedException) error;
            return new ErrorResponse(
                    HttpStatus.FORBIDDEN,
                    "ACCOUNT_LOCKED",
                    String.format("Your account has been locked due to multiple failed login attempts. " +
                                    "Please try again in %d minutes or contact support.",
                            lockedException.getLockoutMinutes()),
                    null,
                    Map.of(
                            "lockoutMinutes", lockedException.getLockoutMinutes(),
                            "unlockTime", lockedException.getUnlockTime(),
                            "contactSupport", true
                    )
            );
        }

        if (error instanceof AccountDisabledException) {
            return new ErrorResponse(
                    HttpStatus.FORBIDDEN,
                    "ACCOUNT_DISABLED",
                    "Your account has been disabled. Please contact support for assistance.",
                    null,
                    Map.of("contactSupport", true)
            );
        }

        // 3. Email Verification Required
        if (error instanceof EmailNotVerifiedException) {
            return new ErrorResponse(
                    HttpStatus.FORBIDDEN,
                    "EMAIL_NOT_VERIFIED",
                    "Please verify your email address before logging in. Check your inbox for the verification link.",
                    null,
                    Map.of(
                            "action", "verify_email",
                            "resendAvailable", true
                    )
            );
        }

        // 4. Password Expiry
        if (error instanceof PasswordExpiredException) {
            PasswordExpiredException pwdError = (PasswordExpiredException) error;
            return new ErrorResponse(
                    HttpStatus.FORBIDDEN,
                    "PASSWORD_EXPIRED",
                    String.format("Your password expired %d days ago. Please reset your password to continue.",
                            pwdError.getDaysExpired()),
                    null,
                    Map.of(
                            "action", "reset_password",
                            "daysExpired", pwdError.getDaysExpired()
                    )
            );
        }

        // 5. Rate Limiting
        if (error instanceof RateLimitExceededException) {
            RateLimitExceededException rateLimitError = (RateLimitExceededException) error;
            return new ErrorResponse(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "RATE_LIMIT_EXCEEDED",
                    String.format("Too many login attempts. Please try again in %d minutes.",
                            rateLimitError.getRetryAfterMinutes()),
                    null,
                    Map.of(
                            "retryAfter", rateLimitError.getRetryAfterMinutes(),
                            "reason", "security_protection"
                    )
            );
        }

        // 6. MFA Required
        //if (error instanceof MfaRequiredException) {
            //return new ErrorResponse(
                    //HttpStatus.FORBIDDEN,
                    //"MFA_REQUIRED",
                    //"Multi-factor authentication is required. Please complete MFA verification.",
                    //null,
                    //Map.of(
                            //"action", "complete_mfa",
                            //"mfaSessionId", ((MfaRequiredException) error).getSessionId()
                    //)
            //);
       // }

        // 7. Session/Token Errors
        if (error instanceof InvalidTokenException) {
            return new ErrorResponse(
                    HttpStatus.UNAUTHORIZED,
                    "INVALID_TOKEN",
                    "Your session has expired. Please log in again.",
                    null,
                    Map.of("action", "relogin")
            );
        }

        if (error instanceof TokenExpiredException) {
            return new ErrorResponse(
                    HttpStatus.UNAUTHORIZED,
                    "TOKEN_EXPIRED",
                    "Your session has expired. Please log in again.",
                    null,
                    Map.of("action", "relogin")
            );
        }

        // 8. Device Verification
        //if (error instanceof UnrecognizedDeviceException) {
            //return new ErrorResponse(
                    //HttpStatus.FORBIDDEN,
                    //"UNRECOGNIZED_DEVICE",
                    //"We detected a login from an unrecognized device. Please verify your identity through the link sent to your email.",
                    //null,
                    //Map.of(
                            //"action", "verify_device",
                            //"emailSent", true
                    //)
            //);
        //}

        // 9. Network & Timeout Errors
        if (error instanceof TimeoutException) {
            return new ErrorResponse(
                    HttpStatus.REQUEST_TIMEOUT,
                    "REQUEST_TIMEOUT",
                    "Login is taking longer than expected. Please try again in a moment.",
                    null,
                    Map.of("retryable", true)
            );
        }

        if (error instanceof NetworkException ||
                error instanceof java.net.ConnectException ||
                error instanceof java.net.UnknownHostException) {
            return new ErrorResponse(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "NETWORK_ERROR",
                    "Unable to connect to authentication service. Please check your internet connection and try again.",
                    null,
                    Map.of("retryable", true)
            );
        }

        // 10. Service Unavailable
        if (error instanceof ServiceUnavailableException) {
            return new ErrorResponse(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "Our authentication service is temporarily unavailable. Please try again in a few minutes.",
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

        // 12. Firebase Authentication Errors
        if (error instanceof FirebaseAuthException) {
            return handleFirebaseAuthError((FirebaseAuthException) error);
        }

        // 13. Transient Errors (Retryable)
        if (error instanceof TransientAuthenticationException) {
            return new ErrorResponse(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "TRANSIENT_ERROR",
                    "A temporary error occurred. Please try again.",
                    null,
                    Map.of("retryable", true)
            );
        }

        // 14. Generic CustomException
        if (error instanceof CustomException) {
            CustomException customError = (CustomException) error;
            return new ErrorResponse(
                    customError.getStatus(),
                    customError.getCode() != null ? customError.getCode() : "AUTH_ERROR",
                    customError.getMessage(),
                    customError.getField(),
                    null
            );
        }

        // 15. Unknown/Unexpected Errors (Fallback)
        log.error("Unexpected authentication error for {}", HelperUtils.maskEmail(email), error);
        return new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "UNEXPECTED_ERROR",
                "An unexpected error occurred during login. Please try again later or contact support if the problem persists.",
                null,
                Map.of(
                        "retryable", true,
                        "contactSupport", true
                )
        );
    }

    /**
     * Handle AuthException with specific error codes.
     */
    private ErrorResponse handleAuthException(AuthException error) {
        String errorCode = error.getErrorCode() != null ? error.getErrorCode() : "AUTH_ERROR";

        // Map common authentication error codes
        switch (errorCode) {
            case "INVALID_CREDENTIALS":
            case "USER_NOT_FOUND":
                return new ErrorResponse(
                        HttpStatus.UNAUTHORIZED,
                        "INVALID_CREDENTIALS",
                        "Invalid email or password. Please check your credentials and try again.",
                        null,
                        Map.of(
                                "action", "retry_or_reset"
                                //"remainingAttempts", error.getAdditionalInfo().getOrDefault("remainingAttempts", 3)
                        )
                );

            case "ACCOUNT_LOCKED":
                return new ErrorResponse(
                        HttpStatus.FORBIDDEN,
                        "ACCOUNT_LOCKED",
                        error.getMessage(),
                        null
                        //error.getAdditionalInfo()
                );

            case "EMAIL_NOT_VERIFIED":
                return new ErrorResponse(
                        HttpStatus.FORBIDDEN,
                        "EMAIL_NOT_VERIFIED",
                        error.getMessage(),
                        null,
                        Map.of("action", "verify_email")
                );

            default:
                return new ErrorResponse(
                        error.getStatus(),
                        errorCode,
                        error.getMessage(),
                        null
                        //error.getAdditionalInfo()
                );
        }
    }

    /**
     * Handle Firebase-specific authentication errors.
     */
    private ErrorResponse handleFirebaseAuthError(FirebaseAuthException error) {
        String errorCode = error.getAuthErrorCode().name();

        switch (errorCode) {
            case "USER_NOT_FOUND":
            case "INVALID_PASSWORD":
                return new ErrorResponse(
                        HttpStatus.UNAUTHORIZED,
                        "INVALID_CREDENTIALS",
                        "Invalid email or password. Please check your credentials and try again.",
                        null,
                        Map.of("action", "retry_or_reset")
                );

            case "USER_DISABLED":
                return new ErrorResponse(
                        HttpStatus.FORBIDDEN,
                        "ACCOUNT_DISABLED",
                        "Your account has been disabled. Please contact support for assistance.",
                        null,
                        Map.of("contactSupport", true)
                );

            case "TOO_MANY_ATTEMPTS_TRY_LATER":
                return new ErrorResponse(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "TOO_MANY_ATTEMPTS",
                        "Too many login attempts. Please try again in 15 minutes.",
                        null,
                        Map.of("retryAfter", 15)
                );

            case "INVALID_EMAIL":
                return new ErrorResponse(
                        HttpStatus.BAD_REQUEST,
                        "INVALID_EMAIL_FORMAT",
                        "Please provide a valid email address.",
                        "email",
                        null
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
                log.warn("Unhandled Firebase auth error code: {}", errorCode);
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
     * Log error with appropriate severity level.
     */
    private void logError(Throwable error, String email, ErrorResponse response) {
        String maskedEmail = HelperUtils.maskEmail(email);

        // Expected business errors - INFO/DEBUG level
        if (error instanceof AuthException && "INVALID_CREDENTIALS".equals(response.getErrorCode())) {
            log.info("Failed login attempt for {}: Invalid credentials", maskedEmail);
        }
        // Account status issues - WARN level
        else if (error instanceof AccountLockedException ||
                error instanceof AccountDisabledException ||
                error instanceof RateLimitExceededException) {
            log.warn("Login blocked for {}: {} - {}", maskedEmail,
                    error.getClass().getSimpleName(), response.getMessage());
        }
        // System errors - ERROR level
        else if (error instanceof DatabaseException ||
                error instanceof ServiceUnavailableException ||
                error instanceof TransientAuthenticationException) {
            log.error("System error during login for {}: {}", maskedEmail, error.getMessage());
        }
        // Security concerns - WARN level
        //else if (error instanceof UnrecognizedDeviceException) {
            //log.warn("Unrecognized device login attempt for {}", maskedEmail);
        //}
        // Other errors - INFO level
        else {
            log.info("Login error for {}: {} - {}", maskedEmail,
                    error.getClass().getSimpleName(), response.getErrorCode());
        }
    }
}
