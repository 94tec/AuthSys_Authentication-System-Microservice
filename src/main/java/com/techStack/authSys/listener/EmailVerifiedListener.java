package com.techStack.authSys.listener;

import com.techStack.authSys.event.EmailVerifiedEvent;
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
 * Email Verified Event Listener
 *
 * Handles email verification events.
 * Sends confirmation email and creates audit log.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class EmailVerifiedListener {

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
     * Handle email verified event
     */
    @Async
    @EventListener
    public void handleEmailVerified(EmailVerifiedEvent event) {
        Instant processingStart = clock.instant();

        log.info("Processing EmailVerifiedEvent at {} for user: {}",
                processingStart,
                HelperUtils.maskEmail(event.getEmail()));

        try {
            // Send verification confirmation email
            sendVerificationConfirmation(event);

            // Log email verification
            logEmailVerification(event);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.info("✅ EmailVerifiedEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    HelperUtils.maskEmail(event.getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process EmailVerifiedEvent at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getEmail()),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "EMAIL_VERIFIED_EVENT_PROCESSING_FAILURE",
                    "Failed to process email verified event: " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Send verification confirmation email
     */
    private void sendVerificationConfirmation(EmailVerifiedEvent event) {
        Instant emailStart = clock.instant();

        try {
            emailService.sendEmailVerificationConfirmation(
                    event.getEmail(),
                    event.getOccurredAt()
            );

            Instant emailEnd = clock.instant();
            Duration emailDuration = Duration.between(emailStart, emailEnd);

            log.info("📧 Verification confirmation sent at {} in {} to: {}",
                    emailEnd,
                    emailDuration,
                    HelperUtils.maskEmail(event.getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to send verification confirmation at {} to {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getEmail()),
                    e.getMessage());

            // Log email failure (non-critical)
            auditLogService.logSystemEvent(
                    "VERIFICATION_CONFIRMATION_EMAIL_FAILURE",
                    "Failed to send verification confirmation to " +
                            HelperUtils.maskEmail(event.getEmail())
            );
        }
    }

    /**
     * Log email verification to audit trail
     */
    private void logEmailVerification(EmailVerifiedEvent event) {
        Instant auditStart = clock.instant();

        try {
            String details = String.format(
                    "Email verified at %s from IP: %s",
                    event.getTimestamp(),
                    event.getIpAddress()
            );

            auditLogService.logUserEvent(
                    event.getUserId(),
                    "EMAIL_VERIFIED",
                    details
            );

            Instant auditEnd = clock.instant();
            Duration auditDuration = Duration.between(auditStart, auditEnd);

            log.debug("Audit log created at {} in {} for email verification: {}",
                    auditEnd,
                    auditDuration,
                    HelperUtils.maskEmail(event.getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to log email verification at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getEmail()),
                    e.getMessage());
        }
    }
}