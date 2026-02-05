package com.techStack.authSys.listener;

import com.techStack.authSys.event.AccountLockedEvent;
import com.techStack.authSys.service.notification.EmailService;
import com.techStack.authSys.service.observability.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Account Locked Event Listener
 *
 * Handles account locked events.
 * Sends notification email and creates security audit log.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AccountLockedListener {

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
     * Handle account locked event
     */
    @Async
    @EventListener
    public void handleAccountLocked(AccountLockedEvent event) {
        Instant processingStart = clock.instant();

        log.warn("Processing AccountLockedEvent at {} for user: {} - Reason: {}",
                processingStart,
                event.getUserId(),
                event.getReason());

        try {
            // Log security event
            logSecurityEvent(event);

            // Send account locked notification email
            sendAccountLockedEmail(event);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.warn("✅ AccountLockedEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    event.getUserId());

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process AccountLockedEvent at {} for user {}: {}",
                    errorTime,
                    event.getUserId(),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "ACCOUNT_LOCKED_EVENT_PROCESSING_FAILURE",
                    "Failed to process account locked event for user " +
                            event.getUserId() + ": " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Log security event to audit trail
     */
    private void logSecurityEvent(AccountLockedEvent event) {
        Instant auditStart = clock.instant();

        try {
            String details = String.format(
                    "Account locked at %s - Reason: %s - IP: %s",
                    event.getTimestamp(),
                    event.getReason(),
                    event.getIpAddress()
            );

            auditLogService.logSecurityEvent(
                    "ACCOUNT_LOCKED",
                    event.getUserId(),
                    details
            );

            Instant auditEnd = clock.instant();
            Duration auditDuration = Duration.between(auditStart, auditEnd);

            log.debug("Security audit log created at {} in {} for user: {}",
                    auditEnd,
                    auditDuration,
                    event.getUserId());

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to log security event at {} for user {}: {}",
                    errorTime,
                    event.getUserId(),
                    e.getMessage());
        }
    }

    /**
     * Send account locked notification email
     */
    private void sendAccountLockedEmail(AccountLockedEvent event) {
        Instant emailStart = clock.instant();

        try {
            emailService.sendAccountLockedNotification(
                    event.getUserId(),
                    event.getReason(),
                    event.getTimestamp()
            );

            Instant emailEnd = clock.instant();
            Duration emailDuration = Duration.between(emailStart, emailEnd);

            log.info("📧 Account locked email sent at {} in {} to user: {}",
                    emailEnd,
                    emailDuration,
                    event.getUserId());

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to send account locked email at {} to user {}: {}",
                    errorTime,
                    event.getUserId(),
                    e.getMessage());

            // Log email failure
            auditLogService.logSystemEvent(
                    "ACCOUNT_LOCKED_EMAIL_FAILURE",
                    "Failed to send account locked email to user " +
                            event.getUserId()
            );
        }
    }
}
