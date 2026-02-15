package com.techStack.authSys.service.auth;

import com.techStack.authSys.config.core.LoginOtpProperties;
import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.dto.response.LoginResponse;
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
import lombok.Getter;
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
 * Unified Authentication Service
 *
 * Complete authentication flow handling ALL cases with rate limiting,
 * monitoring, and proper error handling.
 *
 * Priority Order:
 * 1. FIRST-TIME SETUP (highest priority)
 *    - User has forcePasswordChange = true
 *    - Returns temporary token for password change
 *
 * 2. LOGIN OTP (2FA)
 *    - User has phoneVerified = true
 *    - Login OTP enabled in configuration
 *    - Returns temporary token + sends OTP
 *
 * 3. NORMAL LOGIN (backward compatibility)
 *    - Phone not verified OR OTP disabled
 *    - Returns full access tokens immediately
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final RateLimiterService rateLimiterService;
    private final CredentialValidationService credentialValidationService;
    private final TokenGenerationService tokenGenerationService;
    private final AuthenticationEventService authEventService;
    private final JwtService jwtService;
    private final LoginOtpService loginOtpService;
    private final MeterRegistry meterRegistry;
    private final Clock clock;

    private final LoginOtpProperties loginOtpProperties;

    /* =========================
       Main Login Methods
       ========================= */

    /**
     * Complete login flow returning AuthResult (internal use).
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
                        performAuthentication(email, password, ipAddress, deviceFingerprint, userAgent, permissions)
                )
                .doOnSuccess(authResult -> {
                    timer.stop(meterRegistry.timer("auth.success"));
                    authEventService.handleSuccessfulAuthentication(
                            authResult, ipAddress, timestamp, deviceFingerprint, userAgent);
                })
                .doOnError(e -> {
                    timer.stop(meterRegistry.timer("auth.failure"));
                    authEventService.handleFailedAuthentication(
                            email, source, timestamp, ipAddress, deviceFingerprint, reason, e);
                })
                .onErrorResume(this::normalizeAuthException);
    }

    /**
     * Simplified login for REST API returning LoginResponse.
     */
    public Mono<LoginResponse> login(
            String email,
            String password,
            String ipAddress,
            String deviceFingerprint,
            String userAgent) {

        Instant now = clock.instant();
        log.info("🔐 Login attempt for: {} at {} from IP: {}",
                maskEmail(email), now, ipAddress);

        return rateLimiterService.checkAuthRateLimit(ipAddress, email)
                .then(credentialValidationService.validateAndFetchUser(email, password))
                .flatMap(user -> determineLoginFlow(user))
                .timeout(AUTH_TIMEOUT)
                .retryWhen(buildRetryPolicy())
                .doOnSuccess(response ->
                        log.info("✅ Login processed for {}: firstTime={}, requiresOtp={}",
                                maskEmail(email), response.firstTimeLogin(), response.requiresOtp()))
                .doOnError(e ->
                        log.error("❌ Login failed for {}: {}", maskEmail(email), e.getMessage()));
    }

    /* =========================
       Core Authentication Flow
       ========================= */

    /**
     * Perform authentication with rate limiting and validation.
     */
    private Mono<AuthResult> performAuthentication(
            String email,
            String password,
            String ipAddress,
            String deviceFingerprint,
            String userAgent,
            Set<Permissions> permissions) {

        return rateLimiterService.checkAuthRateLimit(ipAddress, email)
                .then(credentialValidationService.validateAndFetchUser(email, password))
                .flatMap(user -> {
                    // PRIORITY 1: First-time user → password change required
                    if (user.isForcePasswordChange()) {
                        log.warn("⚠️ First-time login detected for: {}", email);
                        return handleFirstTimeSetupRequired(user);
                    }

                    // PRIORITY 2: Phone verified + OTP enabled → send login OTP
                    if (user.isPhoneVerified() && loginOtpProperties.isEnabled()) {
                        log.info("📱 Login OTP required for: {}", email);
                        return handleLoginOtpRequired(user);
                    }

                    // PRIORITY 3: Normal login
                    log.info("✅ Normal login for: {}", email);
                    return tokenGenerationService.generateAndPersistTokens(
                            user, ipAddress, deviceFingerprint, userAgent, permissions);
                });
    }

    /**
     * Determine login flow for REST API (no permissions needed).
     */
    private Mono<LoginResponse> determineLoginFlow(User user) {
        // PRIORITY 1: First-time user
        if (user.isForcePasswordChange()) {
            return handleFirstTimeLoginResponse(user);
        }

        // PRIORITY 2: Login OTP required
        if (user.isPhoneVerified() && loginOtpProperties.isEnabled()) {
            return handleLoginOtpResponse(user);
        }

        // PRIORITY 3: Normal login
        return generateFullAccessTokens(user);
    }

    /* =========================
       First-Time Setup Handlers
       ========================= */

    private Mono<AuthResult> handleFirstTimeSetupRequired(User user) {
        String tempToken = jwtService.generateTemporaryToken(user.getId());
        return Mono.error(new FirstTimeSetupRequiredException(
                user.getId(),
                tempToken,
                "First-time login detected. Please change your password to continue."
        ));
    }

    private Mono<LoginResponse> handleFirstTimeLoginResponse(User user) {
        String tempToken = jwtService.generateTemporaryToken(user.getId());
        return Mono.just(LoginResponse.firstTimeLogin(
                tempToken,
                user.getId(),
                "First-time login detected. Please change your password to continue."
        ));
    }

    /* =========================
       Login OTP Handlers
       ========================= */

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

    private Mono<LoginResponse> handleLoginOtpResponse(User user) {
        return loginOtpService.generateAndSendLoginOtp(user)
                .map(otpResponse -> {
                    if (otpResponse.rateLimited()) {
                        return LoginResponse.rateLimited(otpResponse.message());
                    }
                    return LoginResponse.loginOtpRequired(
                            otpResponse.temporaryToken(),
                            user.getId(),
                            otpResponse.message()
                    );
                });
    }

    /* =========================
       Normal Login Handlers
       ========================= */

    private Mono<LoginResponse> generateFullAccessTokens(User user) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user.getId());

        return Mono.just(LoginResponse.success(
                accessToken,
                refreshToken,
                user,
                "Login successful"
        ));
    }

    /* =========================
       Utility Methods
       ========================= */

    private Retry buildRetryPolicy() {
        return Retry.backoff(MAX_RETRY_ATTEMPTS, RETRY_BACKOFF)
                .filter(this::isRetryableException)
                .onRetryExhaustedThrow((spec, signal) ->
                        new AuthException(
                                "Authentication service unavailable",
                                HttpStatus.SERVICE_UNAVAILABLE
                        ));
    }

    private boolean isRetryableException(Throwable throwable) {
        return throwable instanceof TransientAuthenticationException ||
                throwable instanceof NetworkException;
    }

    private <T> Mono<T> normalizeAuthException(Throwable e) {
        if (e instanceof AuthException) {
            return Mono.error(e);
        }
        log.error("Unexpected authentication error: {}", e.getMessage(), e);
        return Mono.error(new AuthException(
                "Authentication failed. Please try again.",
                HttpStatus.UNAUTHORIZED
        ));
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return email;
        String[] parts = email.split("@");
        if (parts[0].length() <= 2) return "***@" + parts[1];
        return parts[0].substring(0, 2) + "***@" + parts[1];
    }

    /* =========================
       Logout
       ========================= */

    public Mono<Void> logout(String userId) {
        Instant now = clock.instant();
        log.info("🚪 User logged out: {} at {}", userId, now);
        // TODO: Add token to blacklist if implementing token revocation
        return Mono.empty();
    }
}