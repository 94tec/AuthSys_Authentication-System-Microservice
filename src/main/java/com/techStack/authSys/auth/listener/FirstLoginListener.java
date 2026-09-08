package com.techStack.authSys.auth.listener;

import com.techStack.authSys.auth.event.FirstLoginEvent;
import com.techStack.authSys.common.util.HelperUtils;
import com.techStack.authSys.notification.repository.EmailService;
import com.techStack.authSys.security.audit.ActionType;
import com.techStack.authSys.security.audit.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * First Login Event Listener
 *
 * Handles first login events.
 * Sends notification email and creates audit log.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class FirstLoginListener {

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
     * Handle first login event
     */
    @Async
    @EventListener
    public void handleFirstLogin(FirstLoginEvent event) {
        Instant processingStart = clock.instant();

        log.info("Processing FirstLoginEvent at {} for user: {} from IP: {}",
                processingStart,
                HelperUtils.maskEmail(event.getUser().getEmail()),
                event.getIpAddress());

        try {
            // Send first login notification email
            sendFirstLoginEmail(event);

            // Log the first login
            logFirstLogin(event);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.info("✅ FirstLoginEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process FirstLoginEvent at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "FIRST_LOGIN_EVENT_PROCESSING_FAILURE",
                    "Failed to process first login event: " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Send first login notification email
     */
    private void sendFirstLoginEmail(FirstLoginEvent event) {
        Instant emailStart = clock.instant();

        emailService.sendFirstLoginNotification(
                        event.getUser().getEmail(),
                        event.getIpAddress(),
                        event.getEventTimestamp()
                )
                .doOnSuccess(v -> {
                    Instant emailEnd = clock.instant();
                    Duration emailDuration = Duration.between(emailStart, emailEnd);
                    log.info("📧 First login email sent at {} in {} to: {}",
                            emailEnd, emailDuration,
                            HelperUtils.maskEmail(event.getUser().getEmail()));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to send first login email at {} to {}: {}",
                            errorTime,
                            HelperUtils.maskEmail(event.getUser().getEmail()),
                            e.getMessage(), e);
                    auditLogService.logSystemEvent(
                            "FIRST_LOGIN_EMAIL_FAILURE",
                            "Failed to send first login email to " +
                                    HelperUtils.maskEmail(event.getUser().getEmail())
                    );
                })
                .subscribe(); // 🔑 This triggers the actual sending
    }

    /**
     * Log first login to audit trail
     */
    private void logFirstLogin(FirstLoginEvent event) {
        Instant auditStart = clock.instant();

        try {
            auditLogService.logUserEvent(
                    event.getUser(),
                    ActionType.FIRST_LOGIN,
                    buildFirstLoginDetails(event),
                    event.getIpAddress()
            );

            Instant auditEnd = clock.instant();
            Duration auditDuration = Duration.between(auditStart, auditEnd);

            log.debug("Audit log created at {} in {} for first login: {}",
                    auditEnd,
                    auditDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to log first login at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage());
        }
    }

    /**
     * Build detailed first login information
     */
    private String buildFirstLoginDetails(FirstLoginEvent event) {
        StringBuilder details = new StringBuilder();
        details.append("First login from IP: ").append(event.getIpAddress());

        if (event.getDeviceFingerprint() != null) {
            details.append(" | Device: ").append(event.getDeviceFingerprint());
        }

        details.append(" | Event Time: ").append(event.getTimestamp());

        return details.toString();
    }
}