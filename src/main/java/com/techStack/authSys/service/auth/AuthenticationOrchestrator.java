package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.exception.auth.FirstTimeSetupRequiredException;
import com.techStack.authSys.exception.auth.OtpVerificationRequiredException;
import com.techStack.authSys.exception.data.NetworkException;
import com.techStack.authSys.exception.auth.TransientAuthenticationException;
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
 * FIXED:
 * - BUG 1: doOnError no longer fires for expected special flows (first-time setup, OTP)
 * - BUG 2: LoginOtpResponse accessor uses isRateLimited() not rateLimited()
 * - BUG 3: normalizeAuthException preserves FirstTimeSetupRequiredException
 *          and OtpVerificationRequiredException (they extend AuthException)
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
     *
     * ✅ FIX 1: doOnError only fires for REAL failures, not for expected flows
     *    (FirstTimeSetupRequiredException and OtpVerificationRequiredException
     *     are intentional redirects, not failures)
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
                        performAuthenticationWithRetry(
                                email, password, ipAddress, deviceFingerprint, userAgent, permissions)
                )
                .doOnSuccess(authResult -> {
                    timer.stop(meterRegistry.timer("auth.success"));
                    authEventService.handleSuccessfulAuthentication(
                            authResult, ipAddress, timestamp, deviceFingerprint, userAgent);
                })
                .doOnError(e -> {
                    timer.stop(meterRegistry.timer("auth.failure"));

                    // ✅ FIX 1: Skip event for expected special flows - these are NOT failures
                    if (isExpectedAuthRedirect(e)) {
                        log.debug("⚡ Auth redirect (not a failure): {}", e.getClass().getSimpleName());
                        return;
                    }

                    authEventService.handleFailedAuthentication(
                            email, source, timestamp, ipAddress, deviceFingerprint, reason, e);
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
                    // ✅ record accessors — no get/is prefix (LoginOtpResponse is a record)
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
     * Returns true if the throwable is an expected auth redirect, not a real failure.
     *
     * FirstTimeSetupRequiredException → user must change password (expected)
     * OtpVerificationRequiredException → user must verify OTP (expected)
     *
     * These should NOT trigger handleFailedAuthentication()
     */
    private boolean isExpectedAuthRedirect(Throwable e) {
        return e instanceof FirstTimeSetupRequiredException ||
                e instanceof OtpVerificationRequiredException;
    }

    /**
     * Builds retry policy for transient failures only.
     * Special auth exceptions (FirstTimeSetup, OtpRequired) are NOT retried.
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
     * Special auth redirects are excluded (they should propagate immediately).
     */
    private boolean isRetryableException(Throwable throwable) {
        return throwable instanceof TransientAuthenticationException ||
                throwable instanceof NetworkException;
    }

    /**
     * Normalizes all exceptions to AuthException for consistent error handling.
     *
     * ✅ FIX 3: Explicitly preserve expected auth redirects before the catch-all.
     *           Without this, FirstTimeSetupRequiredException and
     *           OtpVerificationRequiredException would be wrapped in a generic
     *           UNAUTHORIZED AuthException, losing the tempToken payload.
     */
    private Mono<AuthResult> normalizeAuthException(Throwable e) {
        // ✅ FIX 3: Let expected redirects propagate as-is (they carry tempToken)
        if (e instanceof FirstTimeSetupRequiredException) {
            return Mono.error(e);
        }

        if (e instanceof OtpVerificationRequiredException) {
            return Mono.error(e);
        }

        // Pass through all other AuthExceptions (rate limit, invalid credentials, etc.)
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