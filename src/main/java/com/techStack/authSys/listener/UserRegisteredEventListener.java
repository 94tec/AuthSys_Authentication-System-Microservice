package com.techStack.authSys.listener;

import com.techStack.authSys.event.UserRegisteredEvent;
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
 * User Registered Event Listener
 *
 * Handles user registration events.
 * Uses Clock for timestamp tracking and audit logging.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserRegisteredEventListener {

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
     * Handle user registered event
     */
    @Async
    @EventListener
    public void handleUserRegisteredEvent(UserRegisteredEvent event) {
        Instant processingStart = clock.instant();

        log.info("Processing UserRegisteredEvent at {} for user: {} from IP: {}",
                processingStart,
                HelperUtils.maskEmail(event.getUser().getEmail()),
                event.getIpAddress());

        try {
            // Send welcome email
            sendWelcomeEmail(event);

            // Log the registration
            logRegistration(event);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.info("✅ UserRegisteredEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process UserRegisteredEvent at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "REGISTRATION_EVENT_PROCESSING_FAILURE",
                    "Failed to process registration event for " +
                            HelperUtils.maskEmail(event.getUser().getEmail()) +
                            ": " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Send welcome email to new user
     */
    private void sendWelcomeEmail(UserRegisteredEvent event) {
        Instant emailStart = clock.instant();

        try {
            emailService.sendWelcomeEmail(
                    event.getUser().getEmail(),
                    event.getIpAddress()
            );

            Instant emailEnd = clock.instant();
            Duration emailDuration = Duration.between(emailStart, emailEnd);

            log.info("📧 Welcome email sent at {} in {} to: {}",
                    emailEnd,
                    emailDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to send welcome email at {} to {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage());

            // Log email failure
            auditLogService.logSystemEvent(
                    "WELCOME_EMAIL_FAILURE",
                    "Failed to send welcome email to " +
                            HelperUtils.maskEmail(event.getUser().getEmail())
            );
        }
    }

    /**
     * Log user registration
     */
    private void logRegistration(UserRegisteredEvent event) {
        Instant auditStart = clock.instant();

        try {
            // Log registration event
            auditLogService.logUserEvent(
                    event.getUser().getId(),
                    "USER_REGISTERED",
                    buildRegistrationDetails(event)
            );

            // Log detailed audit
            auditLogService.logUserEvent(
                    event.getUser(),
                    ActionType.REGISTRATION,
                    buildRegistrationDetails(event),
                    event.getIpAddress()
            );

            // Log registration success
            auditLogService.logRegistrationSuccess(
                    event.getUser().getEmail(),
                    event.getUser().getRoles(),
                    event.getUser().getStatus(),
                    event.getIpAddress()
            );

            Instant auditEnd = clock.instant();
            Duration auditDuration = Duration.between(auditStart, auditEnd);

            log.debug("Audit logs created at {} in {} for user: {}",
                    auditEnd,
                    auditDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to log registration at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage());
        }
    }

    /**
     * Build detailed registration information
     */
    private String buildRegistrationDetails(UserRegisteredEvent event) {
        StringBuilder details = new StringBuilder();
        details.append("New user registered from IP: ").append(event.getIpAddress());

        if (event.getDeviceFingerprint() != null) {
            details.append(" | Device: ").append(event.getDeviceFingerprint());
        }

        if (event.getRequestedRoles() != null && !event.getRequestedRoles().isEmpty()) {
            details.append(" | Requested Roles: ").append(event.getRequestedRoles());
        }

        details.append(" | Status: ").append(event.getUser().getStatus());
        details.append(" | Event Time: ").append(event.getTimestamp());

        return details.toString();
    }
}