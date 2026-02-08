package com.techStack.authSys.listener;

import com.techStack.authSys.event.UserRejectedEvent;
import com.techStack.authSys.repository.notification.EmailService;
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
 * User Rejected Event Listener
 *
 * Handles user rejection events.
 * Sends rejection notification email and creates audit log.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserRejectedListener {

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
     * Handle user rejected event
     */
    @Async
    @EventListener
    public void handleUserRejected(UserRejectedEvent event) {
        Instant processingStart = clock.instant();

        log.warn("Processing UserRejectedEvent at {} for user: {} rejected by: {} - Reason: {}",
                processingStart,
                HelperUtils.maskEmail(event.getEmail()),
                event.getRejectedBy(),
                event.getReason());

        try {
            // Send rejection notification
            sendRejectionNotification(event);

            // Log rejection
            logRejection(event);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.warn("✅ UserRejectedEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    HelperUtils.maskEmail(event.getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process UserRejectedEvent at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getEmail()),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "USER_REJECTED_EVENT_PROCESSING_FAILURE",
                    "Failed to process user rejected event: " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Send rejection notification email
     */
    private void sendRejectionNotification(UserRejectedEvent event) {
        Instant emailStart = clock.instant();

        try {
            emailService.sendUserRejectedNotification(
                    event.getEmail(),
                    event.getReason(),
                    event.getOccurredAt()
            );

            Instant emailEnd = clock.instant();
            Duration emailDuration = Duration.between(emailStart, emailEnd);

            log.info("📧 Rejection notification sent at {} in {} to: {}",
                    emailEnd,
                    emailDuration,
                    HelperUtils.maskEmail(event.getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to send rejection notification at {} to {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getEmail()),
                    e.getMessage());

            // Log email failure
            auditLogService.logSystemEvent(
                    "REJECTION_NOTIFICATION_EMAIL_FAILURE",
                    "Failed to send rejection notification to " +
                            HelperUtils.maskEmail(event.getEmail())
            );
        }
    }

    /**
     * Log user rejection to audit trail
     */
    private void logRejection(UserRejectedEvent event) {
        Instant auditStart = clock.instant();

        try {
            auditLogService.logApprovalAction(
                    event.getUserId(),
                    event.getRejectedBy(),
                    "REJECTED",
                    event.getRejectorRole(),
                    event.getReason()
            );

            Instant auditEnd = clock.instant();
            Duration auditDuration = Duration.between(auditStart, auditEnd);

            log.debug("Audit log created at {} in {} for user rejection: {}",
                    auditEnd,
                    auditDuration,
                    HelperUtils.maskEmail(event.getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to log user rejection at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getEmail()),
                    e.getMessage());
        }
    }
}
