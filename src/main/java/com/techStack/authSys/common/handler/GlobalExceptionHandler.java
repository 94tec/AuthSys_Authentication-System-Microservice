package com.techStack.authSys.common.handler;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.auth.dto.LoginResponse;
import com.techStack.authSys.auth.exception.*;
import com.techStack.authSys.auth.service.AuthenticationErrorHandlerService;
import com.techStack.authSys.auth.service.DeviceVerificationService;
import com.techStack.authSys.auth.service.RegistrationErrorHandlerService;
import com.techStack.authSys.authorization.exception.PermissionDeniedException;
import com.techStack.authSys.common.dto.ApiResponse;
import com.techStack.authSys.common.dto.ErrorResponse;
import com.techStack.authSys.common.exception.*;
import com.techStack.authSys.common.util.HelperUtils;
import com.techStack.authSys.identity.exception.AccountDisabledException;
import com.techStack.authSys.identity.exception.AccountLockedException;
import com.techStack.authSys.identity.exception.InactiveDomainException;
import com.techStack.authSys.identity.exception.InvalidDomainException;
import com.techStack.authSys.security.exception.*;
import com.techStack.authSys.tour.dto.response.QuoteStatusErrorResponse;
import com.techStack.authSys.tour.exception.QuoteExpiredException;
import com.techStack.authSys.tour.exception.QuoteStatusException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

/**
 * Global Exception Handler
 *
 * Provides consistent error responses across the application.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    /* =========================
       Dependencies
       ========================= */

    private final RegistrationErrorHandlerService registrationErrorHandler;
    private final AuthenticationErrorHandlerService authenticationErrorHandler;
    private final DeviceVerificationService deviceVerificationService;
    private final Clock clock;

    /* =========================
       Registration Exceptions
       ========================= */

    /**
     * Handle all registration-related exceptions
     */
    @ExceptionHandler({
            EmailAlreadyExistsException.class,
            ValidationException.class,
            SuspiciousActivityException.class,
            GeolocationBlockedException.class,
            InvalidDomainException.class,
            InactiveDomainException.class,
            WeakPasswordException.class,
            CommonPasswordException.class,
            BotDetectedException.class,
            CacheException.class,
            EmailServiceException.class,
            DeviceFingerprintException.class,
            PermissionDeniedException.class,
            DataIntegrityException.class,
            DataMappingException.class
    })
    public Mono<ResponseEntity<Map<String, Object>>> handleRegistrationExceptions(
            Exception ex, ServerWebExchange exchange) {

        Instant handlingTime = clock.instant();
        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.debug("Handling {} exception at {} for {}: {}",
                operation, handlingTime, sanitizeEmail(email), ex.getClass().getSimpleName());

        return registrationErrorHandler.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response -> logErrorResponse(
                        ex, email, (HttpStatus) response.getStatusCode(), operation, handlingTime)
                );
    }

    /* =========================
       Authentication Exceptions
       ========================= */
    /**
     * Handle first-time setup required
     */
    @ExceptionHandler(FirstTimeSetupRequiredException.class)
    public ResponseEntity<ApiResponse<LoginResponse>> handleFirstTimeSetupRequired(
            FirstTimeSetupRequiredException ex) {

        log.warn("First-time setup required for user: {}", ex.getUserId());

        LoginResponse response = LoginResponse.firstTimeLogin(
                ex.getTemporaryToken(),
                ex.getUserId(),
                ex.getMessage()
        );

        return ResponseEntity
                .status(ex.getHttpStatus())
                .body(ApiResponse.success(ex.getMessage(), response));
    }

    /**
     * Handle OTP verification required
     */
    @ExceptionHandler(OtpVerificationRequiredException.class)
    public ResponseEntity<ApiResponse<LoginResponse>> handleOtpVerificationRequired(
            OtpVerificationRequiredException ex) {

        log.info("OTP verification required for user: {}", ex.getUserId());

        LoginResponse response = LoginResponse.loginOtpRequired(
                ex.getTemporaryToken(),
                ex.getUserId(),
                ex.getMessage()
        );

        return ResponseEntity
                .status(ex.getHttpStatus())
                .body(ApiResponse.success(ex.getMessage(), response));
    }

    /**
     * Handle all authentication-related exceptions
     */
    @ExceptionHandler({
            AuthException.class,
            AccountLockedException.class,
            AccountDisabledException.class,
            EmailNotVerifiedException.class,
            PasswordExpiredException.class,
            InvalidTokenException.class,
            TokenExpiredException.class,
            TransientAuthenticationException.class
    })
    public Mono<ResponseEntity<Map<String, Object>>> handleAuthenticationExceptions(
            Exception ex, ServerWebExchange exchange) {

        Instant handlingTime = clock.instant();
        String email = extractEmailFromRequest(exchange);

        log.debug("Handling authentication exception at {} for {}: {}",
                handlingTime, sanitizeEmail(email), ex.getClass().getSimpleName());

        return authenticationErrorHandler.handleAuthenticationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response -> logErrorResponse(
                        ex, email, (HttpStatus) response.getStatusCode(), "authentication", handlingTime)
                );
    }
    /**
     * Handle bootstrap initialization exceptions
     * These are FATAL and should not be caught during startup
     */
    @ExceptionHandler(BootstrapInitializationException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleBootstrapException(
            BootstrapInitializationException ex, ServerWebExchange exchange) {

        Instant now = clock.instant();
        String email = extractEmailFromRequest(exchange);

        // Unwrap to the real root cause
        Throwable rootCause = unwrapCause(ex);

        log.error("🚨 FATAL BOOTSTRAP ERROR at {} - {}: {}",
                now, rootCause.getClass().getSimpleName(), rootCause.getMessage());

        // EmailAlreadyExistsException → delegate to registration handler (409 Conflict)
        if (rootCause instanceof EmailAlreadyExistsException
                || rootCause instanceof CustomException customEx
                && customEx.getMessage() != null
                && customEx.getMessage().toLowerCase().contains("already")) {
            return registrationErrorHandler
                    .handleRegistrationError(rootCause, email)
                    .map(this::buildErrorResponseEntity);
        }

        // FirebaseAuthException → delegate to registration handler
        if (rootCause instanceof FirebaseAuthException) {
            return registrationErrorHandler
                    .handleRegistrationError(rootCause, email)
                    .map(this::buildErrorResponseEntity);
        }

        // CustomException with known status → delegate to registration handler
        if (rootCause instanceof CustomException) {
            return registrationErrorHandler
                    .handleRegistrationError(rootCause, email)
                    .map(this::buildErrorResponseEntity);
        }

        // True fatal bootstrap failure — keep the 500
        log.error("💥 Unrecoverable bootstrap failure at {}: failurePoint={} retryable={}",
                now, ex.getFailurePoint(), ex.isRetryable());

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.put("errorCode", "BOOTSTRAP_FAILED");
        response.put("message", "Application bootstrap failed - system is not operational");
        response.put("failurePoint", ex.getFailurePoint());
        response.put("retryable", ex.isRetryable());
        response.put("timestamp", now.toString());
        response.put("timestampMillis", now.toEpochMilli());

        return Mono.just(ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(response));
    }

    /* Walks the full cause chain to find the real root exception */
    private Throwable unwrapCause(Throwable ex) {
        Throwable cause = ex;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause;
    }

    /* =========================
       Rate Limit Exceptions
       ========================= */

    /**
     * Handle rate limit exceptions
     */
    @ExceptionHandler(RateLimitExceededException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleRateLimitExceeded(
            RateLimitExceededException ex, ServerWebExchange exchange) {

        Instant now = clock.instant();
        String operation = determineOperation(exchange);

        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("message", ex.getMessage());
        body.put("errorCode", "RATE_LIMIT_EXCEEDED");
        body.put("retryAfterMinutes", ex.getRetryAfterMinutes());
        body.put("timestamp", now.toString());
        body.put("timestampMillis", now.toEpochMilli());

        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", String.valueOf(ex.getRetryAfterMinutes() * 60));

        log.warn("Rate limit exceeded at {} for {} operation from IP: {}",
                now, operation, deviceVerificationService.extractClientIp(exchange));

        return Mono.just(ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .headers(headers)
                .body(body));
    }

    /* =========================
       Shared/Common Exceptions
       ========================= */

    /**
     * Handle service unavailable exceptions
     */
    @ExceptionHandler(ServiceUnavailableException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleServiceUnavailable(
            ServiceUnavailableException ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    /**
     * Handle database exceptions
     */
    @ExceptionHandler(DatabaseException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleDatabaseException(
            DatabaseException ex, ServerWebExchange exchange) {

        Instant now = clock.instant();
        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.error("Database error at {} during {} for {}: {}",
                now, operation, sanitizeEmail(email), ex.getMessage());

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    /**
     * Handle Firebase authentication exceptions
     */
    @ExceptionHandler(FirebaseAuthException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleFirebaseAuthException(
            FirebaseAuthException ex, ServerWebExchange exchange) {

        Instant now = clock.instant();
        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.warn("Firebase auth error at {} during {} for {}: {} - {}",
                now, operation, sanitizeEmail(email), ex.getAuthErrorCode(), ex.getMessage());

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    /**
     * Handle CustomException (generic)
     */
    @ExceptionHandler(CustomException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleCustomException(
            CustomException ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    /* =========================
       Validation Exceptions
       ========================= */

    /**
     * Handle Spring validation errors (Bean Validation)
     */
    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidationExceptions(
            WebExchangeBindException ex) {

        Instant now = clock.instant();

        Map<String, String> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        error -> error.getDefaultMessage() != null ?
                                error.getDefaultMessage() : "Invalid value",
                        (existing, replacement) -> existing
                ));

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("errorCode", "VALIDATION_ERROR");
        response.put("message", "Please correct the following errors and try again");
        response.put("errors", fieldErrors);
        response.put("timestamp", now.toString());
        response.put("timestampMillis", now.toEpochMilli());

        log.debug("Bean validation errors at {}: {}", now, fieldErrors);

        return Mono.just(ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(response));
    }

    /**
     * Handle illegal argument exceptions
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleIllegalArgumentException(
            IllegalArgumentException ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    /* =========================
       Network & Timeout Exceptions
       ========================= */

    /**
     * Handle timeout exceptions
     */
    @ExceptionHandler(TimeoutException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleTimeoutException(
            TimeoutException ex, ServerWebExchange exchange) {

        Instant now = clock.instant();
        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.warn("Request timeout at {} during {} for {}: {}",
                now, operation, sanitizeEmail(email), ex.getMessage());

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    /**
     * Handle network exceptions
     */
    @ExceptionHandler({
            java.net.ConnectException.class,
            java.net.UnknownHostException.class,
            java.io.IOException.class
    })
    public Mono<ResponseEntity<Map<String, Object>>> handleNetworkExceptions(
            Exception ex, ServerWebExchange exchange) {

        Instant now = clock.instant();
        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.error("Network error at {} during {} for {}: {}",
                now, operation, sanitizeEmail(email), ex.getMessage());

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    /**
     * Handle concurrent modification exceptions
     */
    @ExceptionHandler(ConcurrentModificationException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleConcurrentModificationException(
            ConcurrentModificationException ex, ServerWebExchange exchange) {

        Instant now = clock.instant();
        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.warn("Concurrent {} attempt at {} for {}", operation, now, sanitizeEmail(email));

        return registrationErrorHandler.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity);
    }

    /* =========================
       Unexpected Exceptions
       ========================= */

    /**
     * Handle null pointer exceptions
     */
    @ExceptionHandler(NullPointerException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleNullPointerException(
            NullPointerException ex, ServerWebExchange exchange) {

        Instant now = clock.instant();

        log.error("NullPointerException at {} - programming error at path {}",
                now, exchange.getRequest().getPath().value(), ex);

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.put("errorCode", "INTERNAL_ERROR");
        response.put("message", "An internal error occurred. Our team has been notified.");
        response.put("timestamp", now.toString());
        response.put("timestampMillis", now.toEpochMilli());

        return Mono.just(ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(response));
    }

    /**
     * Catch-all handler for unexpected exceptions
     */
    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleGenericException(
            Exception ex, ServerWebExchange exchange) {

        Instant now = clock.instant();
        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.error("Unexpected exception at {} during {} for {}: {}",
                now, operation, sanitizeEmail(email), ex.getMessage(), ex);

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    @ExceptionHandler(QuoteStatusException.class)
    public ResponseEntity<QuoteStatusErrorResponse> handleQuoteStatus(
            QuoteStatusException ex,
            ServerWebExchange exchange
    ) {
        HttpStatus status = ex.status();

        log.info(
                "Quote lifecycle conflict: action={}, quoteId={}, currentStatus={}, " +
                        "allowedStatuses={}, path={}",
                ex.getAction(),
                ex.getQuoteId(),
                ex.getCurrentStatus(),
                ex.getAllowedStatuses(),
                exchange.getRequest().getPath().value()
        );

        QuoteStatusErrorResponse response =
                new QuoteStatusErrorResponse(
                        false,
                        status.value(),
                        "QUOTE_STATUS_CONFLICT",
                        ex.getMessage(),
                        ex.getQuoteId(),
                        ex.getCurrentStatus(),
                        ex.getAllowedStatuses(),
                        ex.getAction()
                );

        return ResponseEntity
                .status(status)
                .body(response);
    }

    @ExceptionHandler(QuoteExpiredException.class)
    public ResponseEntity<Map<String, Object>> handleQuoteExpired(
            QuoteExpiredException ex
    ) {
        Instant now = clock.instant();

        Map<String, Object> response = new HashMap<>();

        response.put("success", false);
        response.put("status", ex.status().value());
        response.put("errorCode", "QUOTE_EXPIRED");
        response.put("message", ex.getMessage());
        response.put("quoteId", ex.getQuoteId());
        response.put("expiredOn", ex.getExpiredOn());
        response.put("timestamp", now.toString());
        response.put("timestampMillis", now.toEpochMilli());

        return ResponseEntity
                .status(ex.status())
                .body(response);
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Build standardized error response entity
     */
    private ResponseEntity<Map<String, Object>> buildErrorResponseEntity(ErrorResponse errorResponse) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("status", errorResponse.getStatusCode());
        response.put("errorCode", errorResponse.getErrorCode());
        response.put("message", errorResponse.getMessage());
        response.put("timestamp", errorResponse.getTimestamp().toString());
        response.put("timestampMillis", errorResponse.getTimestamp().toEpochMilli());

        if (errorResponse.getField() != null) {
            response.put("field", errorResponse.getField());
        }

        if (errorResponse.getAdditionalInfo() != null && !errorResponse.getAdditionalInfo().isEmpty()) {
            response.put("additionalInfo", errorResponse.getAdditionalInfo());
        }

        return ResponseEntity
                .status(errorResponse.getStatus())
                .body(response);
    }

    /**
     * Determine operation type from request path
     */
    private String determineOperation(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value().toLowerCase();

        if (path.contains("/login") || path.contains("/logout") || path.contains("/refresh")) {
            return "authentication";
        } else if (path.contains("/register")) {
            return "registration";
        }

        return "unknown";
    }

    /**
     * Extract email from request
     */
    private String extractEmailFromRequest(ServerWebExchange exchange) {
        try {
            // Try query parameters
            String emailFromQuery = exchange.getRequest().getQueryParams().getFirst("email");
            if (emailFromQuery != null) {
                return emailFromQuery;
            }

            // Try path variable
            String path = exchange.getRequest().getPath().value();
            if (path.contains("email=")) {
                String[] parts = path.split("email=");
                if (parts.length > 1) {
                    return parts[1].split("&")[0];
                }
            }

            return "unknown";
        } catch (Exception e) {
            log.debug("Could not extract email from request: {}", e.getMessage());
            return "unknown";
        }
    }

    /**
     * Sanitize email for logging
     */
    private String sanitizeEmail(String email) {
        return HelperUtils.maskEmail(email);
    }

    /**
     * Log error response with appropriate level
     */
    private void logErrorResponse(
            Exception ex,
            String email,
            HttpStatus status,
            String operation,
            Instant timestamp) {

        String sanitized = sanitizeEmail(email);

        // Expected business errors - INFO level
        if (ex instanceof EmailAlreadyExistsException ||
                ex instanceof RateLimitExceededException ||
                (ex instanceof AuthException &&
                        "INVALID_CREDENTIALS".equals(((AuthException) ex).getErrorCode()))) {
            log.info("{} blocked at {} for {}: {} - {}",
                    operation, timestamp, sanitized, ex.getClass().getSimpleName(), status);
        }
        // Validation errors - DEBUG level
        else if (ex instanceof ValidationException ||
                ex instanceof WeakPasswordException) {
            log.debug("Validation error at {} for {}: {}", timestamp, sanitized, ex.getMessage());
        }
        // Security-related - WARN level
        else if (ex instanceof SuspiciousActivityException ||
                ex instanceof BotDetectedException ||
                ex instanceof AccountLockedException) {
            log.warn("Security event at {} for {}: {}", timestamp, sanitized, ex.getMessage());
        }
        // System errors - ERROR level
        else if (ex instanceof DatabaseException ||
                ex instanceof ServiceUnavailableException) {
            log.error("System error at {} for {}: {}", timestamp, sanitized, ex.getMessage());
        }
        // Other errors - INFO level
        else {
            log.info("Error at {} for {}: {} - {}",
                    timestamp, sanitized, ex.getClass().getSimpleName(), status);
        }
    }
}