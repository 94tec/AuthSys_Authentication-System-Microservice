package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.request.ChangePasswordRequest;
import com.techStack.authSys.dto.request.VerifyOtpRequest;
import com.techStack.authSys.dto.response.OtpResult;
import com.techStack.authSys.dto.response.PasswordChangeResult;
import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.OtpService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.service.user.PasswordChangeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

import static com.techStack.authSys.models.audit.ActionType.FIRST_TIME_SETUP;

/**
 * First-Time Login Setup Service
 *
 * FIXED: Using OtpResult getter methods (isSent(), isRateLimited(), getMessage())
 * instead of record accessors (sent(), rateLimited(), message())
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FirstTimeLoginSetupService {

    private final JwtService jwtService;
    private final OtpService otpService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PasswordChangeService passwordChangeService;
    private final AuditLogService auditLogService;
    private final Clock clock;

    /* =========================
       Step 1 — Change Password & Send OTP
       ========================= */

    public Mono<PasswordChangeResult> changePasswordFirstTime(
            String tempToken,
            ChangePasswordRequest request) {

        Instant now = clock.instant();

        return validateTemporaryToken(tempToken)
                .flatMap(userId -> firebaseServiceAuth.getUserById(userId))
                .flatMap(user -> {
                    if (!user.isForcePasswordChange()) {
                        log.warn("⚠️ User {} is not in first-time setup state", user.getId());
                        return Mono.error(new IllegalStateException(
                                "User is not in first-time setup state"));
                    }

                    log.info("🔑 Changing password for user {} at {}", user.getId(), now);

                    return passwordChangeService.changePasswordFirstTime(
                                    user.getId(),
                                    request.newPassword()
                            )
                            .doOnSuccess(unused ->
                                    log.info("✅ Password changed successfully for user {}", user.getId()))
                            .then(otpService.generateAndSendSetupOtp(user.getId(), user.getPhoneNumber()))
                            .map(otpResult -> {
                                // ✅ FIXED: Use getter methods instead of record accessors
                                boolean otpSent = otpResult.isSent() && !otpResult.isRateLimited();

                                auditPasswordChange(user.getId(), true, otpSent);

                                return new PasswordChangeResult(
                                        otpResult.getMessage(),  // ✅ Use getMessage()
                                        otpSent
                                );
                            })
                            .onErrorResume(ex -> {
                                log.error("❌ Failed to send setup OTP for user {}: {}",
                                        user.getId(), ex.getMessage(), ex);

                                auditPasswordChange(user.getId(), true, false);

                                return Mono.just(new PasswordChangeResult(
                                        "Password changed but failed to send OTP. Please try resending.",
                                        false
                                ));
                            });
                })
                .doOnError(e ->
                        log.error("❌ Password change failed at {}: {}", clock.instant(), e.getMessage()));
    }

    /* =========================
       Step 2 — Verify OTP & Complete Setup
       ========================= */

    public Mono<TokenPair> verifyOtpAndCompleteSetup(
            String tempToken,
            VerifyOtpRequest request) {

        Instant now = clock.instant();

        return validateTemporaryToken(tempToken)
                .flatMap(userId ->
                        otpService.verifySetupOtp(userId, request.otp())
                                .flatMap(result -> {
                                    // ✅ FIXED: Use isValid() getter
                                    if (!result.isValid()) {
                                        log.warn("⚠️ Setup OTP verification failed for user {}: {}",
                                                userId, result.getMessage());
                                        return Mono.error(
                                                new IllegalArgumentException(result.getMessage()));
                                    }

                                    return firebaseServiceAuth.getUserById(userId);
                                })
                )
                .flatMap(user -> {
                    log.info("✅ Setup OTP verified for user: {} at {}", user.getId(), now);

                    user.setPhoneVerified(true);

                    return firebaseServiceAuth.save(user)
                            .thenReturn(user);
                })
                .map(user -> {
                    String accessToken = jwtService.generateAccessToken(user);
                    String refreshToken = jwtService.generateRefreshToken(user.getId());

                    log.info("🎉 First-time setup completed for user: {} at {}", user.getId(), now);

                    auditSetupCompleted(user.getId(), true);

                    return new TokenPair(accessToken, refreshToken);
                })
                .doOnError(e ->
                        log.error("❌ OTP verification failed at {}: {}", now, e.getMessage()));
    }

    /* =========================
       Resend OTP
       ========================= */

    public Mono<OtpResult> resendOtp(String tempToken) {
        Instant now = clock.instant();

        return validateTemporaryToken(tempToken)
                .flatMap(userId -> firebaseServiceAuth.getUserById(userId))
                .flatMap(user -> {
                    log.info("🔄 Resending setup OTP to user: {} at {}", user.getId(), now);
                    return otpService.generateAndSendSetupOtp(user.getId(), user.getPhoneNumber());
                })
                .doOnSuccess(result ->
                        log.info("✅ Setup OTP resent at {}", now))
                .doOnError(e ->
                        log.error("❌ Setup OTP resend failed at {}: {}", now, e.getMessage()));
    }

    /* =========================
       Token Validation
       ========================= */

    private Mono<String> validateTemporaryToken(String token) {
        return Mono.fromCallable(() -> {
            if (token == null || !token.startsWith("Bearer ")) {
                throw new IllegalArgumentException("Invalid token format");
            }

            String jwt = token.substring(7);
            String userId = jwtService.extractUserIdFromTemporaryToken(jwt);

            if (userId == null) {
                throw new IllegalArgumentException("Invalid or expired temporary token");
            }

            return userId;
        });
    }

    /* =========================
       Audit Logging
       ========================= */

    private void auditPasswordChange(String userId, boolean passwordChanged, boolean otpSent) {
        try {
            Map<String, Object> details = Map.of(
                    "userId", userId,
                    "action", "FIRST_TIME_PASSWORD_CHANGE",
                    "passwordChanged", passwordChanged,
                    "otpSent", otpSent,
                    "timestamp", clock.instant().toString()
            );

            auditLogService.logAuditEvent(
                    userId,
                    FIRST_TIME_SETUP,
                    "First-time password change",
                    details
            ).subscribe();
        } catch (Exception e) {
            log.warn("Failed to audit password change: {}", e.getMessage());
        }
    }

    private void auditSetupCompleted(String userId, boolean success) {
        try {
            Map<String, Object> details = Map.of(
                    "userId", userId,
                    "action", "FIRST_TIME_SETUP_COMPLETED",
                    "success", success,
                    "timestamp", clock.instant().toString()
            );

            auditLogService.logAuditEvent(
                    userId,
                    FIRST_TIME_SETUP,
                    "First-time setup completed",
                    details
            ).subscribe();
        } catch (Exception e) {
            log.warn("Failed to audit setup completion: {}", e.getMessage());
        }
    }
}