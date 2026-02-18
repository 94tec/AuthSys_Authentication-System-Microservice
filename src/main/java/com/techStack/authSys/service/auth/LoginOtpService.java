package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.request.VerifyLoginOtpRequest;
import com.techStack.authSys.dto.response.LoginOtpResponse;
import com.techStack.authSys.dto.response.OtpResult;
import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.OtpService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.util.auth.TokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

import static com.techStack.authSys.models.audit.ActionType.LOGIN_OTP;
import static com.techStack.authSys.models.audit.ActionType.LOGIN_OTP_VERIFIED;

/**
 * Login OTP Service
 *
 * FIXED: Using OtpResult and OtpVerificationResult getter methods
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginOtpService {

    private final OtpService otpService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final JwtService jwtService;
    private final AuditLogService auditLogService;
    private final Clock clock;
    private final TokenValidator tokenValidator;

    /* =========================
       Generate Login OTP
       ========================= */

    public Mono<LoginOtpResponse> generateAndSendLoginOtp(User user) {
        Instant now = clock.instant();

        log.info("🔐 Generating login OTP for user: {} at {}", user.getId(), now);

        return otpService.generateAndSendLoginOtp(user.getId(), user.getPhoneNumber())
                .flatMap(result -> {
                    if (result.isRateLimited()) {
                        log.warn("⚠️ Login OTP rate limited for user: {}", user.getId());
                        return Mono.just(LoginOtpResponse.rateLimited(result.getMessage()));
                    }

                    String tempToken = jwtService.generateTemporaryLoginToken(user.getId());

                    auditLoginOtpSent(user.getId(), true);

                    return Mono.just(LoginOtpResponse.otpSent(
                            tempToken,
                            user.getId(),
                            "Login OTP sent to your phone. Please verify to continue."
                    ));
                })
                .doOnSuccess(response ->
                        log.info("✅ Login OTP process initiated for user: {} at {}",
                                user.getId(), now))
                .doOnError(e ->
                        log.error("❌ Failed to generate login OTP for user {} at {}: {}",
                                user.getId(), now, e.getMessage()));
    }

    /* =========================
       Verify Login OTP
       ========================= */

    public Mono<TokenPair> verifyLoginOtpAndComplete(
            String tempToken,
            VerifyLoginOtpRequest request) {

        Instant now = clock.instant();

        return tokenValidator.validateTemporaryLoginToken(tempToken)
                .flatMap(userId ->
                        otpService.verifyLoginOtp(userId, request.otp())
                                .flatMap(result -> {
                                    if (!result.isValid()) {
                                        log.warn("⚠️ Login OTP verification failed for user {}: {}",
                                                userId, result.getMessage());
                                        return Mono.error(
                                                new IllegalArgumentException(result.getMessage()));
                                    }

                                    return firebaseServiceAuth.getUserById(userId);
                                })
                )
                .flatMap(user -> {
                    log.info("✅ Login OTP verified for user: {} at {}", user.getId(), now);

                    String accessToken = jwtService.generateAccessToken(user);
                    String refreshToken = jwtService.generateRefreshToken(user.getId());

                    auditLoginOtpVerified(user.getId(), true);

                    return Mono.just(new TokenPair(accessToken, refreshToken));
                })
                .doOnError(e ->
                        log.error("❌ Login OTP verification failed at {}: {}",
                                now, e.getMessage()));
    }

    /* =========================
       Resend Login OTP
       ========================= */

    public Mono<OtpResult> resendLoginOtp(String tempToken) {
        Instant now = clock.instant();

        return tokenValidator.validateTemporaryLoginToken(tempToken)  // Using TokenValidator
                .flatMap(firebaseServiceAuth::getUserById)
                .flatMap(user -> {
                    log.info("🔄 Resending login OTP to user: {} at {}", user.getId(), now);
                    return otpService.generateAndSendLoginOtp(user.getId(), user.getPhoneNumber());
                })
                .doOnSuccess(result ->
                        log.info("✅ Login OTP resent at {}", now))
                .doOnError(e ->
                        log.error("❌ Login OTP resend failed at {}: {}", now, e.getMessage()));
    }

    /* =========================
       Audit Logging
       ========================= */

    private void auditLoginOtpSent(String userId, boolean success) {
        try {
            Map<String, Object> details = Map.of(
                    "userId", userId,
                    "action", "LOGIN_OTP_SENT",
                    "success", success,
                    "timestamp", clock.instant().toString()
            );

            auditLogService.logAuditEvent(
                    userId,
                    LOGIN_OTP,
                    "Login OTP sent",
                    details
            ).subscribe();
        } catch (Exception e) {
            log.warn("Failed to audit login OTP sent: {}", e.getMessage());
        }
    }

    private void auditLoginOtpVerified(String userId, boolean success) {
        try {
            Map<String, Object> details = Map.of(
                    "userId", userId,
                    "action", LOGIN_OTP_VERIFIED,
                    "success", success,
                    "timestamp", clock.instant().toString()
            );
            auditLogService.logAuditEvent(
                    userId,
                    LOGIN_OTP,
                    "Login OTP verified - access granted",
                    details
            ).subscribe();
        } catch (Exception e) {
            log.warn("Failed to audit login OTP verified: {}", e.getMessage());
        }
    }
}