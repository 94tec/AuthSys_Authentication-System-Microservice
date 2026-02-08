package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.internal.TokenValidationRequest;
import com.techStack.authSys.dto.request.PasswordResetCompleteRequest;
import com.techStack.authSys.dto.request.PasswordResetRequest;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.service.user.PasswordResetService;
import com.techStack.authSys.util.validation.HelperUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Password Reset Controller
 *
 * Handles password reset workflows.
 * Uses Clock for timestamp tracking and duration metrics.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/password-reset")
@RequiredArgsConstructor
public class PasswordResetController {

    /* =========================
       Dependencies
       ========================= */

    private final PasswordResetService passwordResetService;
    private final Clock clock;

    /* =========================
       Password Reset Operations
       ========================= */

    /**
     * Initiate password reset
     *
     * POST /api/v1/password-reset/initiate
     */
    @PostMapping("/initiate")
    public Mono<ResponseEntity<Map<String, Object>>> initiatePasswordReset(
            @Valid @RequestBody PasswordResetRequest request) {

        Instant initiateTime = clock.instant();

        log.info("Password reset initiated at {} for email: {}",
                initiateTime, HelperUtils.maskEmail(request.getEmail()));

        return passwordResetService.initiatePasswordReset(request.getEmail())
                .map(token -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(initiateTime, completionTime);

                    log.info("✅ Password reset email sent at {} in {} to: {}",
                            completionTime,
                            duration,
                            HelperUtils.maskEmail(request.getEmail()));

                    return ResponseEntity.ok(Map.<String, Object>of(
                            "success", true,
                            "message", "Password reset email sent. Please check your inbox.",
                            "timestamp", completionTime.toString(),
                            "timestampMillis", completionTime.toEpochMilli()
                    ));
                })
                .onErrorResume(IllegalArgumentException.class, e -> {
                    Instant errorTime = clock.instant();

                    log.warn("Invalid password reset request at {}: {}",
                            errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(Map.<String, Object>of(
                                    "success", false,
                                    "message", e.getMessage(),
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                })
                .onErrorResume(UserNotFoundException.class, e -> {
                    Instant errorTime = clock.instant();

                    // Don't reveal whether user exists - security best practice
                    log.warn("Password reset attempted for non-existent user at {}", errorTime);

                    return Mono.just(ResponseEntity
                            .ok()
                            .body(Map.<String, Object>of(
                                    "success", true,
                                    "message", "If an account exists with this email, you will receive a password reset link.",
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                })
                .onErrorResume(EmailSendingException.class, e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Email sending failed at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .status(HttpStatus.SERVICE_UNAVAILABLE)
                            .body(Map.<String, Object>of(
                                    "success", false,
                                    "message", "Failed to send reset email. Please try again later.",
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Unexpected error at {}: {}", errorTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(Map.<String, Object>of(
                                    "success", false,
                                    "message", "An unexpected error occurred. Please try again.",
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                });
    }

    /**
     * Validate reset token
     *
     * POST /api/v1/password-reset/validate-token
     */
    @PostMapping("/validate-token")
    public Mono<ResponseEntity<Map<String, Object>>> validateResetToken(
            @Valid @RequestBody TokenValidationRequest request) {

        Instant validationTime = clock.instant();

        log.debug("Token validation request at {}", validationTime);

        return passwordResetService.validateResetToken(request.getToken())
                .map(valid -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(validationTime, completionTime);

                    log.info("✅ Token validation completed at {} in {} - Valid: {}",
                            completionTime, duration, valid);

                    return ResponseEntity.ok(Map.<String, Object>of(
                            "success", true,
                            "valid", valid,
                            "message", valid ? "Token is valid" : "Token is invalid or expired",
                            "timestamp", completionTime.toString(),
                            "timestampMillis", completionTime.toEpochMilli()
                    ));
                })
                .defaultIfEmpty(ResponseEntity
                        .badRequest()
                        .body(Map.<String, Object>of(
                                "success", false,
                                "valid", false,
                                "message", "Token is invalid or expired",
                                "timestamp", clock.instant().toString(),
                                "timestampMillis", clock.instant().toEpochMilli()
                        )))
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Token validation error at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(Map.<String, Object>of(
                                    "success", false,
                                    "valid", false,
                                    "message", "An error occurred during validation",
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                });
    }

    /**
     * Complete password reset
     *
     * POST /api/v1/password-reset/complete
     */
    @PostMapping("/complete")
    public Mono<ResponseEntity<ApiResponse<Void>>> completePasswordReset(
            @Valid @RequestBody PasswordResetCompleteRequest request) {

        Instant resetTime = clock.instant();

        log.info("Password reset completion initiated at {}", resetTime);

        return passwordResetService.resetPassword(
                        request.getToken(),
                        request.getNewPassword()
                )
                .map(success -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(resetTime, completionTime);

                    log.info("✅ Password reset completed at {} in {}",
                            completionTime, duration);

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "Password reset successful. You can now login with your new password.",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(IllegalArgumentException.class, e -> {
                    Instant errorTime = clock.instant();

                    log.warn("Invalid password reset completion at {}: {}",
                            errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(ApiResponse.error(e.getMessage(), errorTime)));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Password reset failed at {}: {}",
                            errorTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(ApiResponse.error(
                                    "Failed to reset password. Please try again.",
                                    errorTime
                            )));
                });
    }
}