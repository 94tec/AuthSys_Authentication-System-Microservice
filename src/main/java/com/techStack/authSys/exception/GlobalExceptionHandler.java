package com.techStack.authSys.exception;

import com.techStack.authSys.dto.ErrorDetails;
import com.techStack.authSys.dto.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.file.AccessDeniedException;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler {

    // ================================================================
    // MOST SPECIFIC HANDLERS FIRST (Higher Priority)
    // ================================================================

    /**
     * Handle CustomException (base custom exception)
     */
    @ExceptionHandler(CustomException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleCustomException(
            CustomException ex,
            ServerWebExchange exchange) {

        log.warn("⚠️ CustomException caught on path {}: {} - {}",
                exchange.getRequest().getPath().value(),
                ex.getStatus(),
                ex.getMessage());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", ex.getStatus().value());
        errorResponse.put("error", ex.getStatus().getReasonPhrase());
        errorResponse.put("message", ex.getMessage());
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", exchange.getRequest().getPath().value());

        return Mono.just(ResponseEntity
                .status(ex.getStatus())
                .body(errorResponse));
    }
    /**
     * Handle EmailAlreadyExistsException
     */
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex,
            ServerWebExchange exchange) {

        log.warn("⚠️ Email already exists on path {}: {}",
                exchange.getRequest().getPath().value(),
                ex.getMessage());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpStatus.CONFLICT.value());
        errorResponse.put("error", "Conflict");
        errorResponse.put("message", "Email address is already registered. Please use a different email or try logging in.");
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", exchange.getRequest().getPath().value());

        return Mono.just(ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(errorResponse));
    }
    /**
     * Handle validation errors
     */
    @ExceptionHandler(org.springframework.web.bind.support.WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidationException(
            org.springframework.web.bind.support.WebExchangeBindException ex,
            ServerWebExchange exchange) {

        log.warn("⚠️ Validation error on path {}", exchange.getRequest().getPath().value());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpStatus.BAD_REQUEST.value());
        errorResponse.put("error", "Validation Failed");
        errorResponse.put("message", "Invalid input data");
        errorResponse.put("errors", ex.getFieldErrors().stream()
                .map(error -> Map.of(
                        "field", error.getField(),
                        "message", error.getDefaultMessage()
                ))
                .toList());
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", exchange.getRequest().getPath().value());

        return Mono.just(ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(errorResponse));
    }
    /**
     * Handle AuthException with custom error codes
     */
    @ExceptionHandler(AuthException.class)

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

    // ================================================================
    // SPECIFIC EXCEPTION HANDLERS BY STATUS CODE
    // ================================================================

    /**
     * 400 BAD REQUEST - Client input errors
     */
    @ExceptionHandler({
            DuplicateUserException.class,
            EmailAlreadyVerifiedException.class,
            InvalidUserDetailsException.class,
            PasswordResetException.class,
            InvalidUserProfileException.class,
            UserProfileUpdateException.class,
            InvalidPasswordException.class,
            TemporaryPasswordExpiredException.class,
            PasswordMismatchException.class
            //IllegalArgumentException.class
    })

    public Mono<ResponseEntity<ErrorDetails>> handleBadRequest(Exception ex, ServerWebExchange exchange) {
        return buildReactiveResponse(ex, exchange, HttpStatus.BAD_REQUEST);
    }

    /**
     * 401 UNAUTHORIZED - Authentication failures
     */
    @ExceptionHandler({
            InvalidTokenException.class,
            UnauthorizedException.class,
            RedisOperationException.class,
            PasswordExpiredException.class,
            PasswordWarningException.class
    })

    public Mono<ResponseEntity<ErrorDetails>> handleUnauthorized(Exception ex, ServerWebExchange exchange) {
        return buildReactiveResponse(ex, exchange, HttpStatus.UNAUTHORIZED);
    }

    /**
     * 403 FORBIDDEN - Authorization/permission failures
     */
    @ExceptionHandler({
            AccessDeniedException.class,
            ForcePasswordResetException.class,
            RateLimitExceededException.class,
            AccountDisabledException.class,
            AccountLockedException.class,
            EmailSendingException.class
    })

    public Mono<ResponseEntity<ErrorDetails>> handleForbidden(Exception ex, ServerWebExchange exchange) {
        return buildReactiveResponse(ex, exchange, HttpStatus.FORBIDDEN);
    }

    /**
     * 404 NOT FOUND - Resource not found
     * REMOVED CustomException from here - it has its own handler above
     */
    @ExceptionHandler({
            ResourceNotFoundException.class,
            UserNotFoundException.class,
            InvalidPaginationParameterException.class,
            UserProfileNotFoundException.class,
            AccountNotFoundException.class
    })

    public Mono<ResponseEntity<ErrorDetails>> handleNotFound(Exception ex, ServerWebExchange exchange) {
        return buildReactiveResponse(ex, exchange, HttpStatus.NOT_FOUND);
    }

    /**
     * 500 INTERNAL SERVER ERROR - System/service failures
     */
    @ExceptionHandler({
            ServiceException.class,
            SessionException.class,
            CacheOperationException.class,
            DeviceVerificationException.class,
            ThreatDetectionException.class
    })

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

    /**
     * Handle IllegalArgumentException
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleIllegalArgument(
            IllegalArgumentException ex,
            ServerWebExchange exchange) {

        log.warn("⚠️ Illegal argument on path {}: {}",
                exchange.getRequest().getPath().value(),
                ex.getMessage());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpStatus.BAD_REQUEST.value());
        errorResponse.put("error", "Bad Request");
        errorResponse.put("message", ex.getMessage());
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", exchange.getRequest().getPath().value());

        return Mono.just(ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(errorResponse));
    }

    /**
     * Handle all other exceptions (catch-all)
     */
    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleGenericException(
            Exception ex,
            ServerWebExchange exchange) {

        log.error("❌ Unexpected exception caught on path {}: {}",
                exchange.getRequest().getPath().value(),
                ex.getMessage(),
                ex);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorResponse.put("error", "Internal Server Error");
        errorResponse.put("message", "An unexpected error occurred. Please try again later.");
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("path", exchange.getRequest().getPath().value());

        return Mono.just(ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse));
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