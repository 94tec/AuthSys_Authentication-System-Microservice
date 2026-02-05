package com.techStack.authSys.listener;

import com.techStack.authSys.event.PasswordChangedEvent;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.service.notification.EmailService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Password Changed Event Listener
 *
 * Handles password change events.
 * Sends security notification email and creates audit log.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PasswordChangedListener {

    /* =========================
       Dependencies
       ========================= */

    private final EmailService emailService;
    private final AuditLogService auditLogService;
    private final Clock clock;

    /* =========================
       Event Handling
       ========================= */

    /**
     * Handle password changed event
     */
    @Async
    @EventListener
    public void handlePasswordChanged(PasswordChangedEvent event) {
        Instant processingStart = clock.instant();

        log.info("Processing PasswordChangedEvent at {} for user: {} from IP: {} (forced: {})",
                processingStart,
                HelperUtils.maskEmail(event.getUser().getEmail()),
                event.getIpAddress(),
                event.isForced());

        try {
            // Send password changed notification
            sendPasswordChangedEmail(event);

            // Log password change
            logPasswordChange(event);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.info("✅ PasswordChangedEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process PasswordChangedEvent at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "PASSWORD_CHANGED_EVENT_PROCESSING_FAILURE",
                    "Failed to process password changed event for " +
                            HelperUtils.maskEmail(event.getUser().getEmail()) +
                            ": " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Send password changed notification email
     */
    private void sendPasswordChangedEmail(PasswordChangedEvent event) {
        Instant emailStart = clock.instant();

        try {
            emailService.sendPasswordChangedNotification(
                    event.getUser().getEmail(),
                    event.getIpAddress(),
                    event.getTimestamp(),
                    event.isForced()
            ).subscribe(
                    null,
                    error -> {
                        Instant errorTime = clock.instant();
                        log.error("❌ Failed to send password changed email at {} to {}: {}",
                                errorTime,
                                HelperUtils.maskEmail(event.getUser().getEmail()),
                                error.getMessage());
                    },
                    () -> {
                        Instant emailEnd = clock.instant();
                        Duration emailDuration = Duration.between(emailStart, emailEnd);

                        log.info("📧 Password changed email sent at {} in {} to: {}",
                                emailEnd,
                                emailDuration,
                                HelperUtils.maskEmail(event.getUser().getEmail()));
                    }
            );

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Exception sending password changed email at {} to {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage());

            // Log email failure
            auditLogService.logSystemEvent(
                    "PASSWORD_CHANGED_EMAIL_FAILURE",
                    "Failed to send password changed email to " +
                            HelperUtils.maskEmail(event.getUser().getEmail()) +
                            ": " + e.getMessage()
            );
        }
    }

    /**
     * Log password change to audit trail
     */
    private void logPasswordChange(PasswordChangedEvent event) {
        Instant auditStart = clock.instant();

        try {
            // Log to password change audit collection
            auditLogService.logPasswordChange(
                    event.getUser().getId(),
                    event.getIpAddress()
            ).subscribe(
                    null,
                    error -> log.error("Failed to log password change: {}", error.getMessage()),
                    () -> log.debug("Password change logged to audit trail")
            );

            // Log to general user event audit
            auditLogService.logUserEvent(
                    event.getUser(),
                    ActionType.PASSWORD_CHANGED,
                    buildPasswordChangeDetails(event),
                    event.getIpAddress()
            );

            Instant auditEnd = clock.instant();
            Duration auditDuration = Duration.between(auditStart, auditEnd);

            log.debug("Audit log created at {} in {} for password change: {}",
                    auditEnd,
                    auditDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to log password change at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage());

            // Log the audit failure
            auditLogService.logSystemEvent(
                    "PASSWORD_CHANGE_AUDIT_FAILURE",
                    "Failed to audit password change for " +
                            HelperUtils.maskEmail(event.getUser().getEmail()) +
                            ": " + e.getMessage()
            );
        }
    }

    /**
     * Build detailed password change information
     */
    private String buildPasswordChangeDetails(PasswordChangedEvent event) {
        StringBuilder details = new StringBuilder();
        details.append("Password changed from IP: ").append(event.getIpAddress());

        if (event.isForced()) {
            details.append(" | Type: FORCED_CHANGE (Admin initiated)");
        } else {
            details.append(" | Type: USER_INITIATED");
        }

        details.append(" | Event Time: ").append(event.getTimestamp());

        return details.toString();
    }
}
