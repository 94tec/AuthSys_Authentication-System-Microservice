package com.techStack.authSys.controller.user;

import com.techStack.authSys.dto.request.ForcePasswordChangeRequest;
import com.techStack.authSys.dto.request.PasswordChangeRequest;
import com.techStack.authSys.dto.request.PasswordResetCompleteRequest;
import com.techStack.authSys.dto.request.PasswordResetRequest;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.service.user.PasswordChangeService;
import com.techStack.authSys.service.user.PasswordResetService;
import com.techStack.authSys.util.validation.HelperUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Password Management Controller
 *
 * Handles all password-related operations with Clock-based tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/password")
@RequiredArgsConstructor
public class PasswordManagementController {

    /* =========================
       Dependencies
       ========================= */

    private final PasswordChangeService passwordChangeService;
    private final PasswordResetService passwordResetService;
    private final Clock clock;

    /* =========================
       User Password Change
       ========================= */

    /**
     * Change password (user-initiated)
     *
     * POST /api/v1/password/change
     */
    @PostMapping("/change")
    @PreAuthorize("isAuthenticated()")
    public Mono<ResponseEntity<ApiResponse<Void>>> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            ServerWebExchange exchange) {

        Instant changeTime = clock.instant();
        String email = userDetails.getUsername();

        log.info("Password change initiated at {} for user: {}",
                changeTime, HelperUtils.maskEmail(email));

        // Validate passwords match
        if (!request.passwordsMatch()) {
            Instant errorTime = clock.instant();
            log.warn("Password confirmation mismatch at {} for: {}",
                    errorTime, HelperUtils.maskEmail(email));

            return Mono.just(ResponseEntity
                    .badRequest()
                    .body(ApiResponse.error(
                            "New password and confirmation do not match",
                            errorTime
                    )));
        }

        // Validate passwords are different
        if (!request.passwordsAreDifferent()) {
            Instant errorTime = clock.instant();
            log.warn("Same password attempt at {} for: {}",
                    errorTime, HelperUtils.maskEmail(email));

            return Mono.just(ResponseEntity
                    .badRequest()
                    .body(ApiResponse.error(
                            "New password must be different from current password",
                            errorTime
                    )));
        }

        return passwordChangeService.changePassword(
                        email,
                        request.getCurrentPassword(),
                        request.getNewPassword()
                )
                .map(user -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(changeTime, completionTime);

                    log.info("✅ Password changed successfully at {} in {} for: {}",
                            completionTime, duration, HelperUtils.maskEmail(email));

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "Password changed successfully",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(IllegalArgumentException.class, e -> {
                    Instant errorTime = clock.instant();
                    log.warn("Invalid password change request at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(ApiResponse.error(e.getMessage(), errorTime)));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Password change failed at {}: {}", errorTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(ApiResponse.error(
                                    "Failed to change password. Please try again.",
                                    errorTime
                            )));
                });
    }

    /* =========================
       Admin Force Password Change
       ========================= */

    /**
     * Force password change (admin-initiated)
     *
     * POST /api/v1/password/force-change
     */
    @PostMapping("/force-change")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<Void>>> forcePasswordChange(
            @Valid @RequestBody ForcePasswordChangeRequest request,
            @AuthenticationPrincipal UserDetails adminDetails) {

        Instant forceTime = clock.instant();
        String adminEmail = adminDetails.getUsername();

        log.warn("🔐 Forced password change initiated at {} by admin: {} for user: {}",
                forceTime,
                HelperUtils.maskEmail(adminEmail),
                request.getUserId());

        // Validate passwords match
        if (!request.passwordsMatch()) {
            Instant errorTime = clock.instant();
            log.warn("Password confirmation mismatch at {}", errorTime);

            return Mono.just(ResponseEntity
                    .badRequest()
                    .body(ApiResponse.error(
                            "New password and confirmation do not match",
                            errorTime
                    )));
        }

        return passwordChangeService.forcePasswordChange(
                        request.getUserId(),
                        request.getNewPassword(),
                        request.getReason(),
                        adminEmail,
                        request.isSendNotification(),
                        request.isRequireChangeOnNextLogin()
                )
                .map(user -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(forceTime, completionTime);

                    log.warn("✅ Forced password change completed at {} in {} for user: {} by admin: {}",
                            completionTime,
                            duration,
                            request.getUserId(),
                            HelperUtils.maskEmail(adminEmail));

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "Password changed successfully. User will be notified.",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Forced password change failed at {}: {}", errorTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(ApiResponse.error(
                                    "Failed to change password. Please try again.",
                                    errorTime
                            )));
                });
    }

    /* =========================
       Password Reset Flow
       ========================= */

    /**
     * Initiate password reset
     *
     * POST /api/v1/password/reset/initiate
     */
    @PostMapping("/reset/initiate")
    public Mono<ResponseEntity<ApiResponse<Void>>> initiatePasswordReset(
            @Valid @RequestBody PasswordResetRequest request) {

        Instant initiateTime = clock.instant();

        log.info("Password reset initiated at {} for: {}",
                initiateTime, HelperUtils.maskEmail(request.getEmail()));

        return passwordResetService.initiatePasswordReset(request.getEmail())
                .map(token -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(initiateTime, completionTime);

                    log.info("✅ Password reset email sent at {} in {}",
                            completionTime, duration);

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "If an account exists with this email, you will receive a password reset link.",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    // Don't reveal if user exists - security best practice
                    log.warn("Password reset process completed at {} (may have failed internally)",
                            errorTime);

                    return Mono.just(ResponseEntity.ok(
                            ApiResponse.success(
                                    "If an account exists with this email, you will receive a password reset link.",
                                    errorTime
                            )
                    ));
                });
    }

    /**
     * Complete password reset
     *
     * POST /api/v1/password/reset/complete
     */
    @PostMapping("/reset/complete")
    public Mono<ResponseEntity<ApiResponse<Void>>> completePasswordReset(
            @Valid @RequestBody PasswordResetCompleteRequest request) {

        Instant resetTime = clock.instant();

        log.info("Password reset completion initiated at {}", resetTime);

        // Validate passwords match
        if (!request.passwordsMatch()) {
            Instant errorTime = clock.instant();
            log.warn("Password confirmation mismatch at {}", errorTime);

            return Mono.just(ResponseEntity
                    .badRequest()
                    .body(ApiResponse.error(
                            "New password and confirmation do not match",
                            errorTime
                    )));
        }

        return passwordResetService.resetPassword(
                        request.getToken(),
                        request.getNewPassword()
                )
                .map(user -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(resetTime, completionTime);

                    log.info("✅ Password reset completed at {} in {} for: {}",
                            completionTime, duration, HelperUtils.maskEmail(user.getEmail()));

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "Password reset successful. You can now login with your new password.",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Password reset failed at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(ApiResponse.error(
                                    "Invalid or expired reset token. Please request a new password reset.",
                                    errorTime
                            )));
                });
    }
}