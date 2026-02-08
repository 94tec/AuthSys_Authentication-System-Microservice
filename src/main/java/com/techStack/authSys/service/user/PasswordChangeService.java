package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.event.PasswordChangedEvent;
import com.techStack.authSys.exception.password.PasswordMismatchException;
import com.techStack.authSys.exception.password.PasswordPolicyViolationException;
import com.techStack.authSys.exception.password.PasswordUpdateException;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserPasswordHistory;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.events.EventPublisherService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;


/**
 * Password Change Service
 *
 * Handles password lifecycle management with Clock-based timestamp tracking:
 * - User-initiated password changes (with current password verification)
 * - Admin-forced password changes (without current password)
 * - Password policy enforcement
 * - Password history tracking
 * - Session invalidation
 * - Audit logging
 * - Event publishing
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordChangeService {

    /* =========================
       Constants
       ========================= */

    private static final int PASSWORD_HISTORY_CHECK_COUNT = 5;

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final PasswordHistoryService passwordHistoryService;
    private final SessionService sessionService;
    private final AuditLogService auditLogService;
    private final EventPublisherService eventPublisherService;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${app.password.expiry-days:90}")
    private int passwordExpiryDays;

    @Value("${app.password.force-change-on-next-login:true}")
    private boolean defaultForceChangeOnNextLogin;

    /* =========================
       User-Initiated Password Change
       ========================= */

    /**
     * Change password (user-initiated, requires current password)
     */
    public Mono<User> changePassword(
            String email,
            String currentPassword,
            String newPassword) {

        Instant changeStart = clock.instant();

        log.info("User password change initiated at {} for: {}",
                changeStart, HelperUtils.maskEmail(email));

        return firebaseServiceAuth.findByEmail(email)
                .switchIfEmpty(Mono.error(() -> {
                    Instant errorTime = clock.instant();
                    log.error("User not found at {} for: {}",
                            errorTime, HelperUtils.maskEmail(email));
                    return new CustomException(HttpStatus.NOT_FOUND, "User not found");
                }))
                .flatMap(user -> verifyCurrentPassword(user, currentPassword, changeStart))
                .flatMap(user -> validateNewPassword(user, newPassword, changeStart))
                .flatMap(user -> checkPasswordHistory(user, newPassword, changeStart))
                .flatMap(user -> updatePassword(user, newPassword, false, null, changeStart))
                .doOnSuccess(user -> {
                    Instant changeEnd = clock.instant();
                    Duration duration = Duration.between(changeStart, changeEnd);

                    log.info("✅ Password changed successfully at {} in {} for: {}",
                            changeEnd, duration, HelperUtils.maskEmail(user.getEmail()));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(changeStart, errorTime);

                    log.error("❌ Password change failed at {} after {} for {}: {}",
                            errorTime, duration, HelperUtils.maskEmail(email), e.getMessage());
                });
    }

    /**
     * Verify current password matches
     */
    private Mono<User> verifyCurrentPassword(
            User user,
            String currentPassword,
            Instant changeStart) {

        Instant verifyTime = clock.instant();

        return Mono.fromCallable(() -> {
            boolean matches = passwordEncoder.matches(currentPassword, user.getPassword());

            if (!matches) {
                Instant errorTime = clock.instant();
                log.warn("Current password verification failed at {} for: {}",
                        errorTime, HelperUtils.maskEmail(user.getEmail()));

                throw new PasswordMismatchException("Current password is incorrect");
            }

            Instant verifyEnd = clock.instant();
            Duration duration = Duration.between(verifyTime, verifyEnd);

            log.debug("Current password verified at {} in {}", verifyEnd, duration);

            return user;
        });
    }

    /* =========================
       Admin-Forced Password Change
       ========================= */

    /**
     * Force password change (admin-initiated, no current password required)
     */
    public Mono<User> forcePasswordChange(
            String userId,
            String newPassword,
            String reason,
            String adminEmail,
            boolean sendNotification,
            boolean requireChangeOnNextLogin) {

        Instant forceStart = clock.instant();

        log.warn("🔐 Forced password change initiated at {} by admin: {} for user: {} - Reason: {}",
                forceStart,
                HelperUtils.maskEmail(adminEmail),
                userId,
                reason);

        return firebaseServiceAuth.getUserById(userId)
                .switchIfEmpty(Mono.error(() -> {
                    Instant errorTime = clock.instant();
                    log.error("User not found at {} for forced change: {}", errorTime, userId);
                    return new CustomException(HttpStatus.NOT_FOUND, "User not found");
                }))
                .flatMap(user -> validateNewPassword(user, newPassword, forceStart))
                .flatMap(user -> checkPasswordHistory(user, newPassword, forceStart))
                .flatMap(user -> updatePassword(
                        user,
                        newPassword,
                        true,
                        adminEmail,
                        forceStart
                ))
                .flatMap(user -> {
                    if (requireChangeOnNextLogin) {
                        user.setForcePasswordChange(true);
                        return firebaseServiceAuth.save(user);
                    }
                    return Mono.just(user);
                })
                .flatMap(user -> {
                    if (sendNotification) {
                        // Publish event for notification
                        eventPublisherService.publishPasswordChanged(
                                user,
                                "system",
                                true
                        );
                    }
                    return Mono.just(user);
                })
                .flatMap(user -> logForcedChange(user, reason, adminEmail))
                .doOnSuccess(user -> {
                    Instant forceEnd = clock.instant();
                    Duration duration = Duration.between(forceStart, forceEnd);

                    log.warn("✅ Forced password change completed at {} in {} for user: {} by admin: {}",
                            forceEnd,
                            duration,
                            userId,
                            HelperUtils.maskEmail(adminEmail));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(forceStart, errorTime);

                    log.error("❌ Forced password change failed at {} after {} for user {}: {}",
                            errorTime, duration, userId, e.getMessage());
                });
    }

    /* =========================
       Password Validation
       ========================= */

    /**
     * Validate new password against policy
     */
    private Mono<User> validateNewPassword(
            User user,
            String newPassword,
            Instant operationStart) {

        Instant validateStart = clock.instant();

        log.debug("Validating new password at {} for: {}",
                validateStart, HelperUtils.maskEmail(user.getEmail()));

        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setPassword(newPassword);
        dto.setEmail(user.getEmail());

        return passwordPolicyService.validatePassword(dto)
                .doOnSuccess(validDto -> {
                    Instant validateEnd = clock.instant();
                    Duration duration = Duration.between(validateStart, validateEnd);

                    log.debug("✅ Password policy validated at {} in {}", validateEnd, duration);
                })
                .thenReturn(user)
                .onErrorMap(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Password policy validation failed at {}: {}",
                            errorTime, e.getMessage());
                    return new PasswordPolicyViolationException(
                            "Password does not meet security requirements: " + e.getMessage()
                    );
                });
    }

    /**
     * Check password history to prevent reuse
     */
    private Mono<User> checkPasswordHistory(
            User user,
            String newPassword,
            Instant operationStart) {

        Instant historyCheckStart = clock.instant();

        log.debug("Checking password history at {} for: {}",
                historyCheckStart, HelperUtils.maskEmail(user.getEmail()));

        return Mono.fromCallable(() -> {
            boolean isRecentlyUsed = user.isPasswordRecentlyUsed(
                    newPassword,
                    PASSWORD_HISTORY_CHECK_COUNT
            );

            if (isRecentlyUsed) {
                Instant errorTime = clock.instant();
                log.warn("Password reuse detected at {} for: {}",
                        errorTime, HelperUtils.maskEmail(user.getEmail()));

                throw new PasswordPolicyViolationException(
                        String.format(
                                "Password has been used recently. Please choose a different password " +
                                        "(cannot reuse last %d passwords)",
                                PASSWORD_HISTORY_CHECK_COUNT
                        )
                );
            }

            Instant historyCheckEnd = clock.instant();
            Duration duration = Duration.between(historyCheckStart, historyCheckEnd);

            log.debug("✅ Password history check passed at {} in {}",
                    historyCheckEnd, duration);

            return user;
        });
    }

    /* =========================
       Password Update
       ========================= */

    /**
     * Update password and perform all related operations
     */
    private Mono<User> updatePassword(
            User user,
            String newPassword,
            boolean forced,
            String adminEmail,
            Instant operationStart) {

        Instant updateStart = clock.instant();
        String ipAddress = user.getLastLoginIp() != null ? user.getLastLoginIp() : "system";

        log.info("Updating password at {} for: {} (forced: {})",
                updateStart, HelperUtils.maskEmail(user.getEmail()), forced);

        // Encode new password
        String encodedPassword = passwordEncoder.encode(newPassword);

        // Update user password fields
        user.setPassword(encodedPassword);
        user.setPasswordLastChanged(updateStart);
        user.setPasswordExpiresAt(updateStart.plus(Duration.ofDays(passwordExpiryDays)));

        if (!forced) {
            user.setForcePasswordChange(false);
        }

        // Add to password history
        user.addPasswordToHistory(
                encodedPassword,
                UserPasswordHistory.PasswordHashAlgorithm.BCRYPT,
                forced ? UserPasswordHistory.PasswordChangeReason.ADMIN_RESET
                        : UserPasswordHistory.PasswordChangeReason.USER_INITIATED,
                ipAddress,
                updateStart
        );

        return firebaseServiceAuth.save(user)
                .doOnSuccess(savedUser -> {
                    Instant saveEnd = clock.instant();
                    Duration duration = Duration.between(updateStart, saveEnd);
                    log.info("✅ Password updated in database at {} in {}", saveEnd, duration);
                })
                // Save history but keep User in the chain
                .flatMap(savedUser -> passwordHistoryService.saveToHistory(savedUser.getId(), newPassword)
                        .thenReturn(savedUser))
                // Invalidate sessions but keep User
                .flatMap(savedUser -> invalidateUserSessions(savedUser, updateStart))
                // Create audit log but keep User
                .flatMap(savedUser -> createAuditLog(savedUser, ipAddress, forced, updateStart))
                // Publish event but keep User
                .flatMap(savedUser -> publishPasswordChangeEvent(savedUser, ipAddress, forced, updateStart))
                .onErrorMap(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to update password at {}: {}", errorTime, e.getMessage());
                    return new PasswordUpdateException("Failed to update password", e);
                });

    }

    /**
     * Invalidate all user sessions
     */
    private Mono<User> invalidateUserSessions(User user, Instant operationStart) {
        Instant invalidateStart = clock.instant();

        log.debug("Invalidating sessions at {} for: {}",
                invalidateStart, HelperUtils.maskEmail(user.getEmail()));

        return sessionService.invalidateAllSessionsForUser(user.getId())
                .doOnSuccess(v -> {
                    Instant invalidateEnd = clock.instant();
                    Duration duration = Duration.between(invalidateStart, invalidateEnd);

                    log.info("✅ All sessions invalidated at {} in {} for: {}",
                            invalidateEnd, duration, HelperUtils.maskEmail(user.getEmail()));
                })
                .thenReturn(user) // ✅ convert Mono<Void> → Mono<User>
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.warn("⚠️ Session invalidation failed at {} (non-critical): {}",
                            errorTime, e.getMessage());
                    return Mono.just(user);
                });
    }


    /**
     * Create audit log entry
     */
    private Mono<User> createAuditLog(
            User user,
            String ipAddress,
            boolean forced,
            Instant operationStart) {

        Instant auditStart = clock.instant();

        log.debug("Creating audit log at {} for: {}",
                auditStart, HelperUtils.maskEmail(user.getEmail()));

        return auditLogService.logPasswordChange(user.getId(), ipAddress)
                .doOnSuccess(v -> {
                    Instant auditEnd = clock.instant();
                    Duration duration = Duration.between(auditStart, auditEnd);

                    log.debug("✅ Audit log created at {} in {}", auditEnd, duration);
                })
                .thenReturn(user)
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Audit logging failed at {} (non-critical): {}",
                            errorTime, e.getMessage());
                    return Mono.just(user); // Continue despite audit failure
                });
    }

    /**
     * Publish password changed event
     */
    private Mono<User> publishPasswordChangeEvent(
            User user,
            String ipAddress,
            boolean forced,
            Instant operationStart) {

        Instant publishStart = clock.instant();

        return Mono.fromRunnable(() -> {
                    eventPublisherService.publishPasswordChanged(user, ipAddress, forced);

                    Instant publishEnd = clock.instant();
                    Duration duration = Duration.between(publishStart, publishEnd);

                    log.debug("✅ Password change event published at {} in {}",
                            publishEnd, duration);
                })
                .thenReturn(user)
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.warn("⚠️ Event publishing failed at {} (non-critical): {}",
                            errorTime, e.getMessage());
                    return Mono.just(user); // Continue despite event failure
                });
    }

    /**
     * Log forced password change
     */
    private Mono<User> logForcedChange(User user, String reason, String adminEmail) {
        Instant logTime = clock.instant();

        String logMessage = String.format(
                "Password forcibly changed at %s by admin %s - Reason: %s",
                logTime,
                HelperUtils.maskEmail(adminEmail),
                reason
        );

        return auditLogService.logUserEvent(
                        user,
                        ActionType.FORCED_PASSWORD_CHANGE,
                        logMessage,
                        "system"
                )
                .thenReturn(user)
                .onErrorResume(e -> {
                    log.error("Failed to log forced change: {}", e.getMessage());
                    return Mono.just(user);
                });
    }

}