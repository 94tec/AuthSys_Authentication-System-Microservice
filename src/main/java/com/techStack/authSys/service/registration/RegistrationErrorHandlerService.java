package com.techStack.authSys.service.registration;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.constants.SecurityConstants;
import com.techStack.authSys.dto.response.ErrorResponse;
import com.techStack.authSys.dto.response.ErrorCode;
import com.techStack.authSys.exception.email.EmailAlreadyExistsException;
import com.techStack.authSys.exception.password.WeakPasswordException;
import com.techStack.authSys.exception.security.RateLimitExceededException;
import com.techStack.authSys.exception.security.SuspiciousActivityException;
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
import java.util.Map;

import static com.techStack.authSys.dto.response.ErrorCode.*;

@Service
@RequiredArgsConstructor
public class RegistrationErrorHandlerService {

    private static final Logger logger = LoggerFactory.getLogger(RegistrationErrorHandlerService.class);
    private final Clock clock;

    public Mono<ErrorResponse> handleRegistrationError(Throwable error, String email) {
        logger.debug("Handling registration error for email: {}", email);

        return Mono.fromCallable(() -> {
            ErrorResponse response = determineErrorResponse(error, email);
            logError(error, email, response);
            return response;
        });
    }

    private ErrorResponse determineErrorResponse(Throwable error, String email) {
        Instant now = clock.instant();

        if (error instanceof EmailAlreadyExistsException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.CONFLICT)
                    .errorCode(EMAIL_ALREADY_EXISTS.getCode())
                    .message("This email address is already registered. Please sign in or use the 'Forgot Password' option.")
                    .field(SecurityConstants.FIELD_EMAIL)
                    .details(Map.of("action", SecurityConstants.ACTION_LOGIN_OR_RESET))
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        }

        if (error instanceof FirebaseAuthException firebaseError) {
            return handleFirebaseAuthError(firebaseError, now);
        }

        if (error instanceof ValidationException validationError) {
            return handleValidationError(validationError, now);
        }

        if (error instanceof RateLimitExceededException rateLimitError) {
            return ErrorResponse.builder()
                    .status(HttpStatus.TOO_MANY_REQUESTS)
                    .errorCode(RATE_LIMIT_EXCEEDED.getCode())
                    .message(String.format("Too many registration attempts. Please try again in %d minutes.",
                            rateLimitError.getRetryAfterMinutes()))
                    .details(Map.of(
                            "retryAfter", rateLimitError.getRetryAfterMinutes(),
                            "reason", "security_protection"
                    ))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        }

        if (error instanceof SuspiciousActivityException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.FORBIDDEN)
                    .errorCode(SUSPICIOUS_ACTIVITY_DETECTED.getCode())
                    .message("We detected unusual activity. For security reasons, registration from your location is temporarily restricted.")
                    .details(Map.of("contactSupport", true))
                    .severity(SecurityConstants.SEVERITY_CRITICAL)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        }

        if (error instanceof WeakPasswordException pwdError) {
            return ErrorResponse.builder()
                    .status(HttpStatus.BAD_REQUEST)
                    .errorCode(WEAK_PASSWORD.getCode())
                    .message(pwdError.getMessage())
                    .field(SecurityConstants.FIELD_PASSWORD)
                    .details(Map.of(
                            "requirements", pwdError.getPasswordRequirements(),
                            "violations", pwdError.getViolations()
                    ))
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        }

        if (error instanceof ServiceUnavailableException) {
            return ErrorResponse.builder()
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .errorCode(SERVICE_UNAVAILABLE.getCode())
                    .message("Our registration service is temporarily unavailable. Please try again in a few minutes.")
                    .details(Map.of(
                            "retryable", true,
                            "estimatedRetryTime", "5 minutes"
                    ))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(now)
                    .build();
        }

        logger.error("Unexpected registration error", error);
        return ErrorResponse.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .errorCode(UNEXPECTED_ERROR.getCode())
                .message("An unexpected error occurred during registration. Please try again later or contact support.")
                .details(Map.of(
                        "retryable", true,
                        "contactSupport", true
                ))
                .severity(SecurityConstants.SEVERITY_CRITICAL)
                .traceId(generateTraceId())
                .timestamp(now)
                .build();
    }

    private ErrorResponse handleFirebaseAuthError(FirebaseAuthException error, Instant timestamp) {
        long ts = timestamp.toEpochMilli();

        return switch (String.valueOf(error.getErrorCode())) {
            case "EMAIL_EXISTS" -> ErrorResponse.builder()
                    .status(HttpStatus.CONFLICT)
                    .errorCode(EMAIL_ALREADY_EXISTS.getCode())
                    .message("This email address is already registered.")
                    .field(SecurityConstants.FIELD_EMAIL)
                    .details(Map.of("action", SecurityConstants.ACTION_LOGIN_OR_RESET))
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId())
                    .timestamp(Instant.ofEpochSecond(ts))
                    .build();

            case "WEAK_PASSWORD" -> ErrorResponse.builder()
                    .status(HttpStatus.BAD_REQUEST)
                    .errorCode(WEAK_PASSWORD.getCode())
                    .message("Password must be at least 6 characters long.")
                    .field(SecurityConstants.FIELD_PASSWORD)
                    .severity(SecurityConstants.SEVERITY_ERROR)
                    .traceId(generateTraceId())
                    .timestamp(Instant.ofEpochSecond(ts))
                    .build();

            default -> ErrorResponse.builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .errorCode(FIREBASE_ERROR.getCode())
                    .message("Authentication service error. Please try again.")
                    .details(Map.of("retryable", true))
                    .severity(SecurityConstants.SEVERITY_WARN)
                    .traceId(generateTraceId())
                    .timestamp(Instant.ofEpochSecond(ts))
                    .build();
        };
    }

    private ErrorResponse handleValidationError(ValidationException error, Instant timestamp) {
        return ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST)
                .errorCode(VALIDATION_ERROR.getCode())
                .message(error.getMessage())
                .field(error.getField())
                .details(error.getValidationErrors())
                .severity(SecurityConstants.SEVERITY_ERROR)
                .traceId(generateTraceId())
                .timestamp(timestamp)
                .build();
    }

    private void logError(Throwable error, String email, ErrorResponse response) {
        logger.error("Registration error for {}: {} - Response: {}",
                email,
                error.getMessage(),
                response.getErrorCode());
    }

    private String generateTraceId() {
        return java.util.UUID.randomUUID().toString();
    }
}
