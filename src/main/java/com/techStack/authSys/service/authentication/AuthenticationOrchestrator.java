package com.techStack.authSys.service.authentication;

import com.techStack.authSys.dto.AuthResult;
import com.techStack.authSys.exception.AuthException;
import com.techStack.authSys.exception.NetworkException;
import com.techStack.authSys.exception.TransientAuthenticationException;
import com.techStack.authSys.repository.RateLimiterService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Set;

/**
 * Orchestrates the complete authentication workflow.
 * Coordinates rate limiting, credential validation, token generation, and monitoring.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationOrchestrator {

    private final RateLimiterService rateLimiterService;
    private final CredentialValidationService credentialValidationService;
    private final TokenGenerationService tokenGenerationService;
    private final AuthenticationEventService authEventService;
    private final MeterRegistry meterRegistry;

    private static final Duration AUTH_TIMEOUT = Duration.ofSeconds(20);
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final Duration RETRY_BACKOFF = Duration.ofMillis(100);

    /**
     * Main authentication entry point.
     * Orchestrates the complete authentication flow with retry logic and monitoring.
     */
    public Mono<AuthResult> authenticate(
            String email,
            String password,
            String ipAddress,
            String deviceFingerprint,
            String userAgent,
            Set<String> permissions) {

        Timer.Sample timer = Timer.start(meterRegistry);

        return Mono.defer(() ->
                        performAuthenticationWithRetry(email, password, ipAddress, deviceFingerprint, userAgent, permissions)
                )
                .doOnSuccess(authResult -> {
                    timer.stop(meterRegistry.timer("auth.success"));
                    authEventService.handleSuccessfulAuthentication(authResult, ipAddress, deviceFingerprint);
                })
                .doOnError(e -> {
                    timer.stop(meterRegistry.timer("auth.failure"));
                    authEventService.handleFailedAuthentication(email, ipAddress, deviceFingerprint, e);
                })
                .onErrorResume(this::normalizeAuthException);
    }

    /**
     * Performs authentication with rate limiting, timeout, and retry logic.
     */
    private Mono<AuthResult> performAuthenticationWithRetry(
            String email,
            String password,
            String ipAddress,
            String deviceFingerprint,
            String userAgent,
            Set<String> permissions) {

        return rateLimiterService.checkAuthRateLimit(ipAddress, email)
                .then(credentialValidationService.validateAndFetchUser(email, password))
                .flatMap(user -> tokenGenerationService.generateAndPersistTokens(
                        user, ipAddress, deviceFingerprint, userAgent,permissions))
                .timeout(AUTH_TIMEOUT)
                .retryWhen(buildRetryPolicy());
    }

    /**
     * Builds retry policy for transient failures.
     */
    private Retry buildRetryPolicy() {
        return Retry.backoff(MAX_RETRY_ATTEMPTS, RETRY_BACKOFF)
                .filter(this::isRetryableException)
                .onRetryExhaustedThrow((spec, signal) ->
                        new AuthException(
                                "Authentication service unavailable",
                                HttpStatus.SERVICE_UNAVAILABLE
                        )
                );
    }

    /**
     * Determines if an exception should trigger a retry.
     */
    private boolean isRetryableException(Throwable throwable) {
        return throwable instanceof TransientAuthenticationException ||
                throwable instanceof NetworkException;
    }

    /**
     * Normalizes all exceptions to AuthException for consistent error handling.
     */
    private Mono<AuthResult> normalizeAuthException(Throwable e) {
        if (e instanceof AuthException) {
            return Mono.error(e);
        }

        log.error("Unexpected authentication error: {}", e.getMessage(), e);
        return Mono.error(new AuthException(
                "Authentication failed. Please try again.",
                HttpStatus.UNAUTHORIZED
        ));
    }
}
