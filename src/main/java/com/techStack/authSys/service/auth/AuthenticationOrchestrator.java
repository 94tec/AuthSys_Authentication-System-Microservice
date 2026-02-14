package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.exception.auth.FirstTimeSetupRequiredException;
import com.techStack.authSys.exception.auth.OtpVerificationRequiredException;
import com.techStack.authSys.exception.data.NetworkException;
import com.techStack.authSys.exception.auth.TransientAuthenticationException;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.security.RateLimiterService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.service.token.TokenGenerationService;
import com.techStack.authSys.service.validation.CredentialValidationService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;

import static com.techStack.authSys.constants.SecurityConstants.*;

/**
 * Orchestrates the complete authentication workflow.
 * Coordinates rate limiting, credential validation, token generation, and monitoring.
 *
 * NOW INCLUDES:
 * - First-time setup detection
 * - Login OTP (2FA) detection
 * - Proper exception handling for special cases
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationOrchestrator {

    private final RateLimiterService rateLimiterService;
    private final CredentialValidationService credentialValidationService;
    private final TokenGenerationService tokenGenerationService;
    private final AuthenticationEventService authEventService;
    private final JwtService jwtService;
    private final LoginOtpService loginOtpService;
    private final MeterRegistry meterRegistry;
    private final Clock clock;

    @Value("${auth.login-otp.enabled:true}")
    private boolean loginOtpEnabled;

    /**
     * Main authentication entry point.
     * Orchestrates the complete authentication flow with retry logic and monitoring.
     */
    public Mono<AuthResult> authenticate(
            String email,
            String password,
            String ipAddress,
            Instant timestamp,
            String deviceFingerprint,
            String userAgent,
            String reason,
            Object source,
            Set<Permissions> permissions) {

        Timer.Sample timer = Timer.start(meterRegistry);

        return Mono.defer(() ->
                        performAuthenticationWithRetry(email, password, ipAddress, deviceFingerprint, userAgent, permissions)
                )
                .doOnSuccess(authResult -> {
                    timer.stop(meterRegistry.timer("auth.success"));
                    authEventService.handleSuccessfulAuthentication(authResult, ipAddress, timestamp, deviceFingerprint, userAgent);
                })
                .doOnError(e -> {
                    timer.stop(meterRegistry.timer("auth.failure"));
                    authEventService.handleFailedAuthentication(email, source, timestamp, ipAddress, deviceFingerprint, reason, e);
                })
                .onErrorResume(this::normalizeAuthException);
    }

    /**
     * Performs authentication with rate limiting, timeout, and retry logic.
     * NOW CHECKS: First-time setup and OTP requirements
     */
    private Mono<AuthResult> performAuthenticationWithRetry(
            String email,
            String password,
            String ipAddress,
            String deviceFingerprint,
            String userAgent,
            Set<Permissions> permissions) {

        return rateLimiterService.checkAuthRateLimit(ipAddress, email)
                .then(credentialValidationService.validateAndFetchUser(email, password))
                .flatMap(user -> {
                    // ✅ CHECK 1: First-time setup required?
                    if (user.isForcePasswordChange()) {
                        log.warn("⚠️ First-time setup required for: {}", email);
                        return handleFirstTimeSetupRequired(user);
                    }

                    // ✅ CHECK 2: Login OTP required?
                    if (user.isPhoneVerified() && loginOtpEnabled) {
                        log.info("📱 Login OTP required for: {}", email);
                        return handleLoginOtpRequired(user);
                    }

                    // ✅ CHECK 3: Normal login - generate tokens
                    log.info("✅ Normal login for: {}", email);
                    return tokenGenerationService.generateAndPersistTokens(
                            user, ipAddress, deviceFingerprint, userAgent, permissions);
                })
                .timeout(AUTH_TIMEOUT)
                .retryWhen(buildRetryPolicy());
    }

    /**
     * Handle first-time setup requirement.
     * Throws exception with temporary token.
     */
    private Mono<AuthResult> handleFirstTimeSetupRequired(User user) {
        String tempToken = jwtService.generateTemporaryToken(user.getId());

        return Mono.error(new FirstTimeSetupRequiredException(
                user.getId(),
                tempToken,
                "First-time login detected. Please change your password to continue."
        ));
    }

    /**
     * Handle login OTP requirement.
     * Sends OTP and throws exception with temporary token.
     */
    private Mono<AuthResult> handleLoginOtpRequired(User user) {
        return loginOtpService.generateAndSendLoginOtp(user)
                .flatMap(otpResponse -> {
                    if (otpResponse.rateLimited()) {
                        return Mono.error(new AuthException(
                                otpResponse.message(),
                                HttpStatus.TOO_MANY_REQUESTS
                        ));
                    }

                    return Mono.error(new OtpVerificationRequiredException(
                            user.getId(),
                            otpResponse.temporaryToken(),
                            otpResponse.message()
                    ));
                });
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