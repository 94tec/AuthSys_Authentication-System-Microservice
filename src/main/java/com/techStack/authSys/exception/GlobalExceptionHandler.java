package com.techStack.authSys.exception;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.dto.ErrorResponse;
import com.techStack.authSys.service.DeviceVerificationService;
import com.techStack.authSys.service.registration.RegistrationErrorHandlerService;
import com.techStack.authSys.service.authentication.AuthenticationErrorHandlerService;
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

import java.util.ConcurrentModificationException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

/**
 * Global exception handler for all authentication and registration operations.
 * Provides consistent error responses across the application.
 */
@Slf4j
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final RegistrationErrorHandlerService registrationErrorHandler;
    private final AuthenticationErrorHandlerService authenticationErrorHandler;
    private final DeviceVerificationService deviceVerificationService;

    // ============================================================================
    // REGISTRATION-SPECIFIC EXCEPTIONS
    // ============================================================================

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

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange); // "registration" or "login"

        log.debug("Handling {} exception for {}: {}",
                operation, sanitizeEmail(email), ex.getClass().getSimpleName());

        return registrationErrorHandler.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response ->
                        logErrorResponse(ex, email, (HttpStatus) response.getStatusCode(), operation)
                );
    }

    // ============================================================================
    // AUTHENTICATION-SPECIFIC EXCEPTIONS
    // ============================================================================

    /**
     * Handle all authentication-related exceptions
     */
    @ExceptionHandler({
            AuthException.class,
            AccountLockedException.class,
            AccountDisabledException.class,
            EmailNotVerifiedException.class,
            PasswordExpiredException.class,
            //MfaRequiredException.class,
            InvalidTokenException.class,
            TokenExpiredException.class,
            //UnrecognizedDeviceException.class,
            TransientAuthenticationException.class
    })
    public Mono<ResponseEntity<Map<String, Object>>> handleAuthenticationExceptions(
            Exception ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);

        log.debug("Handling authentication exception for {}: {}",
                sanitizeEmail(email), ex.getClass().getSimpleName());

        return authenticationErrorHandler.handleAuthenticationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response ->
                        logErrorResponse(ex, email, (HttpStatus) response.getStatusCode(), "authentication")
                );
    }

    // ============================================================================
    // SHARED/COMMON EXCEPTIONS
    // ============================================================================

    /**
     * Handle rate limit exceptions (used by both registration and authentication)
     */
    @ExceptionHandler(RateLimitExceededException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleRateLimitExceeded(
            RateLimitExceededException ex, ServerWebExchange exchange) {

        String operation = determineOperation(exchange);

        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("message", ex.getMessage());
        body.put("errorCode", "RATE_LIMIT_EXCEEDED");
        body.put("retryAfterMinutes", ex.getRetryAfterMinutes());
        body.put("timestamp", System.currentTimeMillis());

        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", String.valueOf(ex.getRetryAfterMinutes() * 60));

        log.warn("Rate limit exceeded for {} operation from IP: {}",
                operation, deviceVerificationService.extractClientIp(exchange));

        return Mono.just(ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .headers(headers)
                .body(body));
    }

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

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.error("Database error during {} for {}: {}",
                operation, sanitizeEmail(email), ex.getMessage());

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

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.warn("Firebase auth error during {} for {}: {} - {}",
                operation, sanitizeEmail(email), ex.getAuthErrorCode(), ex.getMessage());

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

    // ============================================================================
    // VALIDATION EXCEPTIONS
    // ============================================================================

    /**
     * Handle Spring validation errors (Bean Validation)
     */
    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidationExceptions(
            WebExchangeBindException ex) {

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
        response.put("timestamp", System.currentTimeMillis());

        log.debug("Bean validation errors: {}", fieldErrors);

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

    // ============================================================================
    // NETWORK & TIMEOUT EXCEPTIONS
    // ============================================================================

    /**
     * Handle timeout exceptions
     */
    @ExceptionHandler(TimeoutException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleTimeoutException(
            TimeoutException ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.warn("Request timeout during {} for {}: {}",
                operation, sanitizeEmail(email), ex.getMessage());

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

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.error("Network error during {} for {}: {}",
                operation, sanitizeEmail(email), ex.getMessage());

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

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.warn("Concurrent {} attempt for {}", operation, sanitizeEmail(email));

        return registrationErrorHandler.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity);
    }

    // ============================================================================
    // UNEXPECTED EXCEPTIONS
    // ============================================================================

    /**
     * Handle null pointer exceptions
     */
    @ExceptionHandler(NullPointerException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleNullPointerException(
            NullPointerException ex, ServerWebExchange exchange) {

        log.error("NullPointerException - programming error at path {}",
                exchange.getRequest().getPath().value(), ex);

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.put("errorCode", "INTERNAL_ERROR");
        response.put("message", "An internal error occurred. Our team has been notified.");
        response.put("timestamp", System.currentTimeMillis());

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

        String email = extractEmailFromRequest(exchange);
        String operation = determineOperation(exchange);

        log.error("Unexpected exception during {} for {}: {}",
                operation, sanitizeEmail(email), ex.getMessage(), ex);

        return (operation.equals("authentication")
                ? authenticationErrorHandler.handleAuthenticationError(ex, email)
                : registrationErrorHandler.handleRegistrationError(ex, email))
                .map(this::buildErrorResponseEntity);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    /**
     * Build standardized error response entity
     */
    private ResponseEntity<Map<String, Object>> buildErrorResponseEntity(ErrorResponse errorResponse) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("status", errorResponse.getStatusCode());
        response.put("errorCode", errorResponse.getErrorCode());
        response.put("message", errorResponse.getMessage());
        response.put("timestamp", errorResponse.getTimestamp());

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
     * Determine operation type (registration vs authentication) from request path
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
        if (email == null || email.equals("unknown")) {
            return "unknown";
        }
        if (email.contains("@")) {
            String[] parts = email.split("@");
            return parts[0] + "@***";
        }
        return email;
    }

    /**
     * Log error response with appropriate level
     */
    private void logErrorResponse(Exception ex, String email, HttpStatus status, String operation) {
        String sanitized = sanitizeEmail(email);

        // Expected business errors - INFO level
        if (ex instanceof EmailAlreadyExistsException ||
                ex instanceof RateLimitExceededException ||
                (ex instanceof AuthException && "INVALID_CREDENTIALS".equals(
                        ((AuthException) ex).getErrorCode()))) {
            log.info("{} blocked for {}: {} - {}",
                    operation, sanitized, ex.getClass().getSimpleName(), status);
        }
        // Validation errors - DEBUG level
        else if (ex instanceof ValidationException ||
                ex instanceof WeakPasswordException) {
            log.debug("Validation error for {}: {}", sanitized, ex.getMessage());
        }
        // Security-related - WARN level
        else if (ex instanceof SuspiciousActivityException ||
                ex instanceof BotDetectedException ||
                ex instanceof AccountLockedException ) {
            log.warn("Security event for {}: {}", sanitized, ex.getMessage());
        }
        // System errors - ERROR level
        else if (ex instanceof DatabaseException ||
                ex instanceof ServiceUnavailableException) {
            log.error("System error for {}: {}", sanitized, ex.getMessage());
        }
        // Other errors - INFO level
        else {
            log.info("Error for {}: {} - {}", sanitized, ex.getClass().getSimpleName(), status);
        }
    }
}