package com.techStack.authSys.exception;

import com.techStack.authSys.dto.ErrorDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.file.AccessDeniedException;
import java.util.Date;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private Mono<ResponseEntity<ErrorDetails>> buildReactiveResponse(
            Exception ex, ServerWebExchange exchange, HttpStatus status) {

        log.error("{}: {}", ex.getClass().getSimpleName(), ex.getMessage(), ex);
        ErrorDetails details = new ErrorDetails(
                new Date(),
                ex.getMessage(),
                exchange.getRequest().getPath().value()
        );
        return Mono.just(ResponseEntity.status(status).body(details));
    }

    // ---- 400 BAD REQUEST ----
    @ExceptionHandler({
            DuplicateUserException.class,
            EmailAlreadyVerifiedException.class,
            InvalidUserDetailsException.class,
            PasswordResetException.class,
            InvalidUserProfileException.class,
            UserProfileUpdateException.class,
            InvalidPasswordException.class,
            TemporaryPasswordExpiredException.class,
            PasswordMismatchException.class,
            IllegalArgumentException.class
    })
    public Mono<ResponseEntity<ErrorDetails>> handleBadRequest(Exception ex, ServerWebExchange exchange) {
        return buildReactiveResponse(ex, exchange, HttpStatus.BAD_REQUEST);
    }

    // ---- 401 UNAUTHORIZED ----
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

    // ---- 403 FORBIDDEN ----
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

    // ---- 404 NOT FOUND ----
    @ExceptionHandler({
            ResourceNotFoundException.class,
            UserNotFoundException.class,
            CustomException.class,
            InvalidPaginationParameterException.class,
            UserProfileNotFoundException.class,
            AccountNotFoundException.class
    })
    public Mono<ResponseEntity<ErrorDetails>> handleNotFound(Exception ex, ServerWebExchange exchange) {
        return buildReactiveResponse(ex, exchange, HttpStatus.NOT_FOUND);
    }

    // ---- 500 INTERNAL SERVER ERROR ----
    @ExceptionHandler({
            ServiceException.class,
            SessionException.class,
            CacheOperationException.class,
            DeviceVerificationException.class,
            ThreatDetectionException.class,
            Exception.class
    })
    public Mono<ResponseEntity<ErrorDetails>> handleServerError(Exception ex, ServerWebExchange exchange) {
        String safeMessage = "User registration failed due to an unexpected error.";
        ErrorDetails details = new ErrorDetails(
                new Date(),
                safeMessage,
                exchange.getRequest().getPath().value()
        );
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(details));
    }

    // ----  Custom AuthException (with status + code) ----
    @ExceptionHandler(AuthException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleAuth(AuthException ex) {
        return Mono.just(ResponseEntity
                .status(ex.getStatus())
                .body(Map.of(
                        "message", ex.getMessage(),
                        "status", ex.getStatus().value(),
                        "errorCode", ex.getErrorCode(),
                        "timestamp", ex.getTimestamp().toString()
                )));
    }
}
