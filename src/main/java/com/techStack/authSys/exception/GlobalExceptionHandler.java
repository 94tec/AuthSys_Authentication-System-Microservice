package com.techStack.authSys.exception;

import com.techStack.authSys.dto.ErrorDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;

import java.nio.file.AccessDeniedException;
import java.util.Date;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private ResponseEntity<ErrorDetails> buildResponseEntity(Exception ex, ServerWebExchange exchange, HttpStatus status) {
        log.error("{}: {}", ex.getClass().getSimpleName(), ex.getMessage(), ex);
        ErrorDetails errorDetails = new ErrorDetails(new Date(), ex.getMessage(), exchange.getRequest().getPath().value());
        return new ResponseEntity<>(errorDetails, status);
    }

    @ExceptionHandler({
            DuplicateUserException.class,
            EmailAlreadyVerifiedException.class,
            InvalidUserDetailsException.class,
            PasswordResetException.class,
            InvalidUserProfileException.class,
            UserProfileUpdateException.class
    })
    public ResponseEntity<?> handleBadRequestExceptions(Exception ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({
            InvalidTokenException.class,
            UnauthorizedException.class,
            RedisOperationException.class,
            PasswordExpiredException.class,
            PasswordWarningException.class
    })
    public ResponseEntity<?> handleUnauthorizedExceptions(Exception ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler({
            AccessDeniedException.class,
            ForcePasswordResetException.class,
            RateLimitExceededException.class,
            AccountDisabledException.class,
            AccountLockedException.class,
            EmailSendingException.class
    })
    public ResponseEntity<?> handleForbiddenExceptions(Exception ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler({
            ResourceNotFoundException.class,
            UserNotFoundException.class,
            CustomException.class,
            InvalidPaginationParameterException.class,
            UserProfileNotFoundException.class,
            AccountNotFoundException.class
    })
    public ResponseEntity<?> handleNotFoundExceptions(Exception ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(ServiceException.class)
    public ResponseEntity<?> handleServiceException(ServiceException ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler({
            InvalidPasswordException.class,
            TemporaryPasswordExpiredException.class,
            PasswordMismatchException.class
    })
    public ResponseEntity<?> handlePasswordExceptions(Exception ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleIllegalArgumentException(IllegalArgumentException ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGlobalException(Exception ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    @ExceptionHandler(SessionException.class)
    public ResponseEntity<?> handleSessionException(SessionException ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    @ExceptionHandler(CacheOperationException.class)
    public ResponseEntity<String> handleCacheOperationException(CacheOperationException ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Cache operation failed: " + ex.getMessage());
    }
    @ExceptionHandler(DeviceVerificationException.class)
    public ResponseEntity<String> handleDeviceVerificationException(DeviceVerificationException ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Operation failed: " + ex.getMessage());
    }
    @ExceptionHandler(ThreatDetectionException.class)
    public ResponseEntity<?> handleThreatDetectionException(ThreatDetectionException ex, ServerWebExchange exchange) {
        return buildResponseEntity(ex, exchange, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuth(AuthException ex) {
        return ResponseEntity
                .status(ex.getStatus())
                .body(Map.of(
                        "message", ex.getMessage(),
                        "status", ex.getStatus().value(),
                        "errorCode", ex.getErrorCode(),
                        "timestamp", ex.getTimestamp().toString()
                ));
    }
}
