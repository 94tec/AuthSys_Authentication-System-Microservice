package com.techStack.authSys.exception;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.dto.ErrorDetails;
import com.techStack.authSys.dto.ErrorResponse;
import com.techStack.authSys.service.RegistrationErrorHandlerService;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @Autowired
    private RegistrationErrorHandlerService errorHandlerService;

    /**
     * Handle all registration-related exceptions
     */
    @ExceptionHandler({
            EmailAlreadyExistsException.class,
            ValidationException.class,
            //RateLimitExceededException.class,
            SuspiciousActivityException.class,
            GeolocationBlockedException.class,
            InvalidDomainException.class,
            InactiveDomainException.class,
            WeakPasswordException.class,
            CommonPasswordException.class,
            ServiceUnavailableException.class,
            DatabaseException.class,
            BotDetectedException.class,
            CacheException.class,
            EmailServiceException.class,
            DeviceFingerprintException.class,
            PermissionDeniedException.class,
            DataIntegrityException.class,
            CustomException.class
    })

    public Mono<ResponseEntity<Map<String, Object>>> handleRegistrationExceptions(
            Exception ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);

        return errorHandlerService.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response ->
                        logErrorResponse(ex, email, (HttpStatus) response.getStatusCode())
                );
    }

    /**
     * Handle Firebase authentication exceptions
     */
    @ExceptionHandler(FirebaseAuthException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleFirebaseAuthException(
            FirebaseAuthException ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);

        return errorHandlerService.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response ->
                        logger.warn("Firebase auth error for {}: {} - {}",
                                sanitizeEmail(email),
                                ex.getErrorCode(),
                                ex.getMessage())
                );
    }

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
                        (existing, replacement) -> existing // Keep first error for duplicate fields
                ));

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("errorCode", "VALIDATION_ERROR");
        response.put("message", "Please correct the following errors and try again");
        response.put("errors", fieldErrors);
        response.put("timestamp", System.currentTimeMillis());

        logger.debug("Bean validation errors: {}", fieldErrors);

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

        return errorHandlerService.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity);
    }

    /**
     * Handle timeout exceptions
     */
    @ExceptionHandler(TimeoutException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleTimeoutException(
            TimeoutException ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);
        return errorHandlerService.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response ->
                        logger.warn("Request timeout for {}: {}", sanitizeEmail(email), ex.getMessage())
                );
    }
    /**
     * Handle rate limit exceed exceptions
     */
    @ExceptionHandler(RateLimitExceededException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleRateLimitExceeded(RateLimitExceededException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("message", ex.getMessage());
        body.put("retryAfterMinutes", ex.getRetryAfterMinutes());
        body.put("timestamp", System.currentTimeMillis());

        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", String.valueOf(ex.getRetryAfterMinutes() * 60)); // in seconds

        return Mono.just(ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .headers(headers)
                .body(body));
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
        return errorHandlerService.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response ->
                        logger.error("Network error for {}: {}", sanitizeEmail(email), ex.getMessage())
                );
    }

    /**
     * Handle concurrent modification exceptions
     */
    @ExceptionHandler(ConcurrentModificationException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleConcurrentModificationException(
            ConcurrentModificationException ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);

        return errorHandlerService.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity)
                .doOnNext(response ->
                        logger.warn("Concurrent registration attempt for {}", sanitizeEmail(email))
                );
    }

    /**
     * Handle null pointer exceptions (should be rare)
     */
    @ExceptionHandler(NullPointerException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleNullPointerException(
            NullPointerException ex, ServerWebExchange exchange) {

        logger.error("NullPointerException occurred - this indicates a programming error", ex);

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

        // Log unexpected exceptions with full stack trace
        logger.error("Unexpected exception during request processing for {}: {}",
                sanitizeEmail(email), ex.getMessage(), ex);

        return errorHandlerService.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity);
    }

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

        // Add field-specific error if present
        if (errorResponse.getField() != null) {
            response.put("field", errorResponse.getField());
        }

        // Add additional info if present
        if (errorResponse.getAdditionalInfo() != null && !errorResponse.getAdditionalInfo().isEmpty()) {
            response.put("additionalInfo", errorResponse.getAdditionalInfo());
        }

        return ResponseEntity
                .status(errorResponse.getStatus())
                .body(response);
    }

    /**
     * Extract email from request for logging purposes
     */
    /**
     * Extract email from request (from body, params, or headers)
     */
    private String extractEmailFromRequest(ServerWebExchange exchange) {
        try {
            // Try query parameters first
            String emailFromQuery = exchange.getRequest().getQueryParams().getFirst("email");
            if (emailFromQuery != null) {
                return emailFromQuery;
            }

            // Try path variable (if email is in URL)
            String path = exchange.getRequest().getPath().value();
            if (path.contains("email=")) {
                String[] parts = path.split("email=");
                if (parts.length > 1) {
                    return parts[1].split("&")[0];
                }
            }

            // For POST requests, email is typically in body (handled by service layer)
            return "unknown";

        } catch (Exception e) {
            logger.debug("Could not extract email from request: {}", e.getMessage());
            return "unknown";
        }

    }
    /**
     * Sanitize email for logging (mask domain)
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
    private void logErrorResponse(Exception ex, String email, HttpStatus status) {
        String sanitized = sanitizeEmail(email);

        // Expected business errors - INFO level
        if (ex instanceof EmailAlreadyExistsException ||
                ex instanceof RateLimitExceededException) {
            logger.info("Registration blocked for {}: {} - {}", sanitized, ex.getClass().getSimpleName(), status);
        }
        // Validation errors - DEBUG level
        else if (ex instanceof ValidationException ||
                ex instanceof WeakPasswordException) {
            logger.debug("Validation error for {}: {}", sanitized, ex.getMessage());
        }
        // Security-related - WARN level
        else if (ex instanceof SuspiciousActivityException ||
                ex instanceof BotDetectedException) {
            logger.warn("Security event for {}: {}", sanitized, ex.getMessage());
        }
        // System errors - ERROR level
        else if (ex instanceof DatabaseException ||
                ex instanceof ServiceUnavailableException) {
            logger.error("System error for {}: {}", sanitized, ex.getMessage());
        }
        // Other errors - WARN level
        else {
            logger.warn("Error for {}: {} - {}", sanitized, ex.getClass().getSimpleName(), status);
        }
    }

    /// ////////////////////////////////fix code below

    /**
     * Handle AuthException with custom error codes
     */
    @ExceptionHandler(AuthException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleRegistrationExceptions(
            AuthException ex, ServerWebExchange exchange) {

        String email = extractEmailFromRequest(exchange);

        return errorHandlerService.handleRegistrationError(ex, email)
                .map(this::buildErrorResponseEntity);
    }

    public Mono<ResponseEntity<Map<String, Object>>> handleAuth(AuthException ex, ServerWebExchange exchange) {
        log.warn("⚠️ AuthException caught: {} - Status: {} - ErrorCode: {} - Path: {}",
                ex.getMessage(), ex.getStatus(), ex.getErrorCode(), exchange.getRequest().getPath().value());

        return Mono.just(ResponseEntity
                .status(ex.getStatus())
                .body(Map.of(
                        "message", ex.getMessage(),
                        "status", ex.getStatus().value(),
                        "errorCode", ex.getErrorCode(),
                        "timestamp", ex.getTimestamp().toString(),
                        "path", exchange.getRequest().getPath().value()
                )));
    }


    public Mono<ResponseEntity<ErrorDetails>> handleServerError(Exception ex, ServerWebExchange exchange) {
        String safeMessage = "An internal server error occurred. Please try again later.";
        ErrorDetails details = new ErrorDetails(
                new Date(),
                safeMessage,
                exchange.getRequest().getPath().value()
        );
        log.error("❌ Internal server error on path {}: {}",
                exchange.getRequest().getPath().value(), ex.getMessage(), ex);
        return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(details));
    }

    // ================================================================
    // HELPER METHODS
    // ================================================================

    /**
     * Build a standardized reactive error response
     */
    private Mono<ResponseEntity<ErrorDetails>> buildReactiveResponse(
            Exception ex, ServerWebExchange exchange, HttpStatus status) {

        log.error("{} on path {}: {}",
                ex.getClass().getSimpleName(),
                exchange.getRequest().getPath().value(),
                ex.getMessage(),
                ex);

        ErrorDetails details = new ErrorDetails(
                new Date(),
                ex.getMessage(),
                exchange.getRequest().getPath().value()
        );
        return Mono.just(ResponseEntity.status(status).body(details));
    }
}