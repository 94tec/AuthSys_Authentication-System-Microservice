package com.techStack.authSys.listener;

import com.techStack.authSys.event.AuthSuccessEvent;
import com.techStack.authSys.models.audit.ActionType;
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
 * Auth Success Listener
 *
 * Handles authentication success events.
 * Uses Clock for timestamp tracking and audit logging.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthSuccessListener {

    /* =========================
       Dependencies
       ========================= */

    private final AuditLogService auditLogService;
    private final Clock clock;

    /* =========================
       Event Handling
       ========================= */

    /**
     * Handle authentication success event
     */
    @Async
    @EventListener
    public void onAuthSuccess(AuthSuccessEvent event) {
        Instant processingStart = clock.instant();

        log.info("Processing AuthSuccessEvent at {} for user: {} from IP: {}",
                processingStart,
                HelperUtils.maskEmail(event.getUser().getEmail()),
                event.getIpAddress());

        try {
            // Log successful authentication
            auditLogService.logLoginAttempt(
                    event.getUser().getEmail(),
                    event.getIpAddress(),
                    true
            );

            // Log detailed user event
            auditLogService.logUserEvent(
                    event.getUser(),
                    ActionType.LOGIN,
                    buildAuthDetails(event),
                    event.getIpAddress()
            );

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.info("✅ AuthSuccessEvent processed at {} in {} for user: {}",
                    processingEnd,
                    processingDuration,
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process AuthSuccessEvent at {} for user {}: {}",
                    errorTime,
                    HelperUtils.maskEmail(event.getUser().getEmail()),
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "AUTH_EVENT_PROCESSING_FAILURE",
                    "Failed to process auth success event: " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Build detailed authentication information
     */
    private String buildAuthDetails(AuthSuccessEvent event) {
        StringBuilder details = new StringBuilder();
        details.append("Successful authentication");

        if (event.getDeviceFingerprint() != null) {
            details.append(" | Device: ").append(event.getDeviceFingerprint());
        }

        if (event.getUserAgent() != null) {
            details.append(" | User-Agent: ").append(event.getUserAgent());
        }

        details.append(" | Event Time: ").append(event.getTimestamp());

        return details.toString();
    }
}