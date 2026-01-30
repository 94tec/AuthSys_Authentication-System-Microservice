package com.techStack.authSys.service.auth;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.constants.SecurityConstants;
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

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static com.techStack.authSys.dto.response.ErrorCode.*;

/**
 * Centralized error handling service for authentication operations.
 * Translates technical exceptions into user-friendly error responses.
 */
@Slf4j
@Service
public class AuthenticationErrorHandlerService {

    private final Clock clock;

    public AuthenticationErrorHandlerService(Clock clock) {
        this.clock = clock;
    }

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
        Instant now = clock.instant();
        if (error instanceof AuthException authError) {
            return handleAuthException(authError, now);
        } if (error instanceof AccountLockedException lockedException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.FORBIDDEN)
                    .errorCode(ACCOUNT_LOCKED.getCode())
                    .message(String
                            .format("Your account has been locked due to multiple failed login attempts. " + "Please try again in %d minutes or contact support.",
                                    lockedException.getLockoutMinutes()))
                    .details(
                            Map.of( "lockoutMinutes", lockedException.getLockoutMinutes(), "unlockTime", lockedException.getUnlockTime(), "contactSupport", true ))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof AccountDisabledException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.FORBIDDEN)
                    .errorCode(ACCOUNT_DISABLED.getCode())
                    .message("Your account has been disabled. Please contact support for assistance.")
                    .details(Map.of("contactSupport", true))
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof EmailNotVerifiedException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.FORBIDDEN)
                    .errorCode(EMAIL_NOT_VERIFIED.getCode())
                    .message("Please verify your email address before logging in. Check your inbox for the verification link.")
                    .details(Map.of( "action", "verify_email", "resendAvailable", true ))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof PasswordExpiredException pwdError) {
            return ErrorResponse.builder()
                    .status(HttpStatus.FORBIDDEN)
                    .errorCode(PASSWORD_EXPIRED.getCode())
                    .message(String.format("Your password expired %d days ago. Please reset your password to continue.", pwdError.getDaysExpired()))
                    .details(Map.of( "action", "reset_password", "daysExpired", pwdError.getDaysExpired() ))
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof RateLimitExceededException rateLimitError) {
            return ErrorResponse.builder()
                    .status(HttpStatus.TOO_MANY_REQUESTS)
                    .errorCode(RATE_LIMIT_EXCEEDED.getCode())
                    .message(String.format("Too many login attempts. Please try again in %d minutes.", rateLimitError.getRetryAfterMinutes()))
                    .details(Map.of( "retryAfter", rateLimitError.getRetryAfterMinutes(), "reason", "security_protection" ))
                    .severity(SecurityConstants.SEVERITY_WARN) .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof InvalidTokenException || error instanceof TokenExpiredException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.UNAUTHORIZED)
                    .errorCode(error instanceof InvalidTokenException ? INVALID_TOKEN.getCode() : TOKEN_EXPIRED.getCode())
                    .message("Your session has expired. Please log in again.")
                    .details(Map.of("action", "relogin"))
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId()) .timestamp(now)
                    .build();
        } if (error instanceof TimeoutException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.REQUEST_TIMEOUT)
                    .errorCode(REQUEST_TIMEOUT.getCode())
                    .message("Login is taking longer than expected. Please try again in a moment.")
                    .details(Map.of("retryable", true))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof NetworkException || error instanceof java.net.ConnectException || error instanceof java.net.UnknownHostException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .errorCode(NETWORK_ERROR.getCode())
                    .message("Unable to connect to authentication service. Please check your internet connection and try again.")
                    .details(Map.of("retryable", true))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof ServiceUnavailableException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .errorCode(SERVICE_UNAVAILABLE.getCode())
                    .message("Our authentication service is temporarily unavailable. Please try again in a few minutes.")
                    .details(Map.of( "retryable", true, "estimatedRetryTime", "5 minutes" ))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof DatabaseException || error.getMessage().contains("UNAVAILABLE") || error.getMessage().contains("DEADLINE_EXCEEDED")) {
            return ErrorResponse.builder()
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .errorCode(DATABASE_ERROR.getCode())
                    .message("We're experiencing technical difficulties. Please try again shortly.")
                    .details(Map.of("retryable", true))
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof FirebaseAuthException firebaseError) { return handleFirebaseAuthError(firebaseError, now); } if (error instanceof TransientAuthenticationException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .errorCode(TRANSIENT_ERROR.getCode())
                    .message("A temporary error occurred. Please try again.") .details(Map.of("retryable", true))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } if (error instanceof CustomException customError) {
            return ErrorResponse.builder()
                    .status(customError.getStatus())
                    .errorCode(customError.getCode() != null ? customError.getCode() : AUTH_ERROR.getCode())
                    .message(customError.getMessage())
                    .field(customError.getField())
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        } log.error("Unexpected authentication error for {}", HelperUtils.maskEmail(email), error);
        return ErrorResponse.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .errorCode(UNEXPECTED_ERROR.getCode())
                .message("An unexpected error occurred during login. Please try again later or contact support if the problem persists.")
                .details(Map.of( "retryable", true, "contactSupport", true ))
                .severity(SecurityConstants.SEVERITY_CRITICAL)
                .traceId(generateTraceId())
                .timestamp(now)
                .build();
    }

    /**
     * Handle AuthException with specific error codes.
     */
    private ErrorResponse handleAuthException(AuthException error, Instant now) {
        String code = error.getErrorCode() != null ? error.getErrorCode() : AUTH_ERROR.getCode();

        switch (code) {
            case "INVALID_CREDENTIALS":
            case "USER_NOT_FOUND":
                return ErrorResponse.builder()
                        .status(HttpStatus.UNAUTHORIZED)
                        .errorCode(INVALID_CREDENTIALS.getCode())
                        .message("Invalid email or password. Please check your credentials and try again.")
                        .details(Map.of(
                                "action", "retry_or_reset"
                                // "remainingAttempts", error.getAdditionalInfo().getOrDefault("remainingAttempts", 3)
                        ))
                        .severity(SecurityConstants.SEVERITY_ERROR)
                        .traceId(generateTraceId())
                        .timestamp(now)
                        .build();

            case "ACCOUNT_LOCKED":
                return ErrorResponse.builder()
                        .status(HttpStatus.FORBIDDEN)
                        .errorCode(ACCOUNT_LOCKED.getCode())
                        .message(error.getMessage())
                        .severity(SecurityConstants.SEVERITY_WARN)
                        .traceId(generateTraceId())
                        .timestamp(now)
                        .build();

            case "EMAIL_NOT_VERIFIED":
                return ErrorResponse.builder()
                        .status(HttpStatus.FORBIDDEN)
                        .errorCode(EMAIL_NOT_VERIFIED.getCode())
                        .message(error.getMessage())
                        .details(Map.of("action", "verify_email"))
                        .severity(SecurityConstants.SEVERITY_WARN)
                        .traceId(generateTraceId())
                        .timestamp(now)
                        .build();

            default:
                return ErrorResponse.builder()
                        .status(error.getStatus())
                        .errorCode(code)
                        .message(error.getMessage())
                        .severity(SecurityConstants.SEVERITY_ERROR)
                        .traceId(generateTraceId())
                        .timestamp(now)
                        .build();
        }
    }
    /**
     * Handle Firebase-specific authentication errors.
     */
    private ErrorResponse handleFirebaseAuthError(FirebaseAuthException error, Instant now) {
        long timestamp = now.toEpochMilli();

        return switch (String.valueOf(error.getErrorCode())) {
            case "EMAIL_EXISTS" -> ErrorResponse.builder()
                    .status(HttpStatus.CONFLICT)
                    .errorCode(EMAIL_ALREADY_EXISTS.getCode())
                    .message("This email address is already registered.")
                    .field(SecurityConstants.FIELD_EMAIL)
                    .details(Map.of(
                            SecurityConstants.DETAIL_ACTION,
                            SecurityConstants.ACTION_LOGIN_OR_RESET
                    ))
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .timestamp(Instant.ofEpochSecond(timestamp))
                    .build();

            case "WEAK_PASSWORD" -> ErrorResponse.builder()
                    .status(HttpStatus.BAD_REQUEST)
                    .errorCode(WEAK_PASSWORD.getCode())
                    .message("Password does not meet security requirements.")
                    .field(SecurityConstants.FIELD_PASSWORD)
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .timestamp(Instant.ofEpochSecond(timestamp))
                    .build();

            default -> ErrorResponse.builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .errorCode(FIREBASE_ERROR.getCode())
                    .message("Authentication service error. Please try again.")
                    .details(Map.of(
                            SecurityConstants.DETAIL_RETRYABLE, true
                    ))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .timestamp(Instant.ofEpochSecond(timestamp))
                    .build();
        };
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
    private String generateTraceId() {
        return java.util.UUID.randomUUID().toString();
    }
}
