package com.techStack.authSys.listener;

import com.techStack.authSys.event.UserApprovedEvent;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.service.notification.BrevoEmailService;
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
 * User Approved Event Listener
 *
 * Handles user approval events.
 * Sends approval notification email and creates audit log.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserApprovedListener {

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
     * Handle user approved event
     */
    @Async
    @EventListener
    public void handleUserApproved(UserApprovedEvent event) {
        Instant processingStart = clock.instant();

        log.info("Processing UserApprovedEvent at {} for user: {} approved by: {}",
                processingStart,
                HelperUtils.maskEmail(event.getUser().getEmail()),
                event.getApprovedBy());

        try {
            // Send approval notification
            sendApprovalNotification(event);

            // Log approval
            logApproval(event);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.info("✅ UserApprovedEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process UserApprovedEvent at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "USER_APPROVED_EVENT_PROCESSING_FAILURE",
                    "Failed to process user approved event: " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Send approval notification email
     */
    private void sendApprovalNotification(UserApprovedEvent event) {
        Instant emailStart = clock.instant();

        try {
            emailService.sendUserApprovedNotification(
                    event.getUser().getEmail(),
                    event.getApprovedBy(),
                    event.getTimestamp()
            );

            Instant emailEnd = clock.instant();
            Duration emailDuration = Duration.between(emailStart, emailEnd);

            log.info("📧 Approval notification sent at {} in {} to: {}",
                    emailEnd,
                    emailDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to send approval notification at {} to {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage());

            // Log email failure
            auditLogService.logSystemEvent(
                    "APPROVAL_NOTIFICATION_EMAIL_FAILURE",
                    "Failed to send approval notification to " +
                            HelperUtils.maskEmail(event.getUser().getEmail())
            );
        }
    }

    /**
     * Log user approval to audit trail
     */
    private void logApproval(UserApprovedEvent event) {
        Instant auditStart = clock.instant();

        try {
            auditLogService.logApprovalAction(
                    event.getUser().getId(),
                    event.getApprovedBy(),
                    "APPROVED",
                    event.getApproverRole()
            );

            auditLogService.logUserEvent(
                    event.getUser(),
                    ActionType.USER_APPROVED,
                    buildApprovalDetails(event),
                    "system"
            );

            Instant auditEnd = clock.instant();
            Duration auditDuration = Duration.between(auditStart, auditEnd);

            log.debug("Audit log created at {} in {} for user approval: {}",
                    auditEnd,
                    auditDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to log user approval at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage());
        }
    }

    /**
     * Build detailed approval information
     */
    private String buildApprovalDetails(UserApprovedEvent event) {
        return String.format(
                "User approved at %s by %s (%s)",
                event.getTimestamp(),
                event.getApprovedBy(),
                event.getApproverRole()
        );
    }
}
