package com.techStack.authSys.listener;

import com.techStack.authSys.event.AccountLockedEvent;
import com.techStack.authSys.repository.notification.EmailService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
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
    private final FirebaseServiceAuth firebaseServiceAuth;  // ✅ Added to fetch user
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

        log.warn("🔒 Processing AccountLockedEvent at {} for user: {} - Reason: {}",
                processingStart,
                event.getUserId(),
                event.getReason());

        try {
            // Log security event
            logSecurityEvent(event, processingStart);

            // Fetch user and send notification email
            sendAccountLockedEmail(event, processingStart);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.warn("✅ AccountLockedEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    event.getUserId());

        } catch (Exception e) {
            Instant errorTime = clock.instant();
            Duration errorDuration = Duration.between(processingStart, errorTime);

            log.error("❌ Failed to process AccountLockedEvent at {} after {} for user {}: {}",
                    errorTime,
                    errorDuration,
                    event.getUserId(),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "ACCOUNT_LOCKED_EVENT_PROCESSING_FAILURE",
                    String.format("Failed to process account locked event for user %s at %s: %s",
                            event.getUserId(), errorTime, e.getMessage())
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Log security event to audit trail
     */
    private void logSecurityEvent(AccountLockedEvent event, Instant processingStart) {
        Instant auditStart = clock.instant();

        try {
            String details = String.format(
                    "Account locked at %s - Reason: %s - IP: %s",
                    event.getEventTime(),
                    event.getReason(),
                    event.getIpAddress() != null ? HelperUtils.maskIpAddress(event.getIpAddress()) : "Unknown"
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
    private void sendAccountLockedEmail(AccountLockedEvent event, Instant processingStart) {
        Instant emailStart = clock.instant();

        try {
            // ✅ Fetch user to get email address
            firebaseServiceAuth.getUserById(event.getUserId())
                    .flatMap(user -> {
                        String email = user.getEmail();

                        log.info("Sending account locked email to: {}",
                                HelperUtils.maskEmail(email));

                        // ✅ Send email with proper parameters
                        return emailService.sendAccountLockedNotification(
                                email,
                                event.getEventTime(),
                                event.getReason(),
                                event.getIpAddress()
                        );
                    })
                    .doOnSuccess(v -> {
                        Instant emailEnd = clock.instant();
                        Duration emailDuration = Duration.between(emailStart, emailEnd);

                        log.info("✅ Account locked email sent at {} in {} for user: {}",
                                emailEnd,
                                emailDuration,
                                event.getUserId());
                    })
                    .doOnError(e -> {
                        Instant errorTime = clock.instant();
                        Duration errorDuration = Duration.between(emailStart, errorTime);

                        log.error("❌ Failed to send account locked email at {} after {} for user {}: {}",
                                errorTime,
                                errorDuration,
                                event.getUserId(),
                                e.getMessage());

                        // Log email failure
                        auditLogService.logSystemEvent(
                                "ACCOUNT_LOCKED_EMAIL_FAILURE",
                                String.format("Failed to send account locked email to user %s at %s: %s",
                                        event.getUserId(), errorTime, e.getMessage())
                        );
                    })
                    .subscribe();  // ✅ Subscribe to execute the Mono

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Error in sendAccountLockedEmail at {} for user {}: {}",
                    errorTime,
                    event.getUserId(),
                    e.getMessage(),
                    e);
        }
    }
}