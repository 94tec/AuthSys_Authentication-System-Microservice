package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.response.LoginResponse;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.token.JwtService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;

/**
 * Complete Authentication Service
 *
 * Unified authentication flow handling ALL cases:
 * 1. First-time login (forcePasswordChange = true)
 * 2. Login with 2FA/OTP (phoneVerified = true, loginOtpEnabled = true)
 * 3. Normal login (backward compatibility)
 *
 * Priority Order:
 * 1. FIRST-TIME SETUP (highest priority)
 *    - User has forcePasswordChange = true
 *    - Returns temporary token for password change
 *    - Must complete setup before anything else
 *
 * 2. LOGIN OTP (2FA)
 *    - User has phoneVerified = true
 *    - Login OTP enabled in configuration
 *    - Returns temporary token + sends OTP
 *    - Must verify OTP to get full access
 *
 * 3. NORMAL LOGIN (backward compatibility)
 *    - Phone not verified OR OTP disabled
 *    - Returns full access tokens immediately
 *    - Legacy flow for existing users
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final JwtService jwtService;
    private final LoginOtpService loginOtpService;
    private final Clock clock;

    /**
     * -- GETTER --
     *  Check if login OTP is enabled.
     */
    @Getter
    @Value("${auth.login-otp.enabled:true}")
    private boolean loginOtpEnabled;

    /* =========================
       Main Login Method
       ========================= */

    /**
     * Complete login flow with all variants.
     *
     * @param email User email
     * @param password User password
     * @return LoginResponse (various states)
     */
    public Mono<LoginResponse> login(String email, String password) {
        Instant now = clock.instant();

        log.info("🔐 Login attempt for: {} at {}", email, now);

        return firebaseServiceAuth.validateCredentials(email, password)
                .then(firebaseServiceAuth.findByEmail(email))
                .flatMap(user -> {
                    // PRIORITY 1: First-time user → password change required
                    if (user.isForcePasswordChange()) {
                        log.warn("⚠️ First-time login detected for: {} at {}", email, now);
                        return handleFirstTimeLogin(user);
                    }

                    // PRIORITY 2: Phone verified + OTP enabled → send login OTP
                    if (user.isPhoneVerified() && loginOtpEnabled) {
                        log.info("📱 Sending login OTP for: {} at {}", email, now);
                        return handleLoginOtp(user);
                    }

                    // PRIORITY 3: Phone not verified OR OTP disabled → full access
                    log.info("✅ Direct login (no OTP) for: {} at {}", email, now);
                    return generateFullAccessTokens(user);
                })
                .doOnSuccess(response ->
                        log.info("✅ Login processed for {} at {}: firstTime={}, requiresOtp={}",
                                email, clock.instant(),
                                response.firstTimeLogin(),
                                response.requiresOtp()))
                .doOnError(e ->
                        log.error("❌ Login failed for {} at {}: {}",
                                email, clock.instant(), e.getMessage()));
    }

    /* =========================
       Handler Methods
       ========================= */

    /**
     * Handle first-time login.
     * Returns temporary token for password change + OTP verification.
     */
    private Mono<LoginResponse> handleFirstTimeLogin(User user) {
        Instant now = clock.instant();

        log.info("🔑 Initiating first-time login flow for: {} at {}",
                user.getEmail(), now);

        // Generate temporary token (FIRST_TIME_SETUP scope, 30 min expiry)
        String tempToken = jwtService.generateTemporaryToken(user.getId());

        // Note: OTP is NOT sent at login — only after password change
        return Mono.just(LoginResponse.firstTimeLogin(
                tempToken,
                user.getId(),
                "First-time login detected. Please change your password to continue."
        ));
    }

    /**
     * Handle login OTP (2FA).
     * Sends OTP and returns temporary token for verification.
     */
    private Mono<LoginResponse> handleLoginOtp(User user) {
        Instant now = clock.instant();

        log.info("📱 Initiating login OTP flow for: {} at {}",
                user.getEmail(), now);

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

    /**
     * Generate full access tokens.
     * Normal login complete — no additional steps required.
     */
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
       Logout
       ========================= */

    /**
     * Logout user (invalidate tokens).
     * TODO: Implement token blacklisting if needed.
     */
    public Mono<Void> logout(String userId) {
        Instant now = clock.instant();
        log.info("🚪 User logged out: {} at {}", userId, now);
        // TODO: Add token to blacklist if implementing token revocation
        return Mono.empty();
    }

    /* =========================
       Configuration Checks
       ========================= */

}