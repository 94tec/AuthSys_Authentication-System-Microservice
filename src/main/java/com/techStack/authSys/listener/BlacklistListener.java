package com.techStack.authSys.listener;

import com.techStack.authSys.event.BlacklistRemovedEvent;
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
 * Blacklist Event Listener
 *
 * Handles blacklist-related events.
 * Creates security audit logs for blacklist operations.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BlacklistListener {

    /* =========================
       Dependencies
       ========================= */

    private final AuditLogService auditLogService;
    private final Clock clock;

    /* =========================
       Event Handling
       ========================= */

    /**
     * Handle blacklist removed event
     */
    @Async
    @EventListener
    public void handleBlacklistRemoved(BlacklistRemovedEvent event) {
        Instant processingStart = clock.instant();

        log.info("Processing BlacklistRemovedEvent at {} - Removed by: {}",
                processingStart,
                event.getRemovedBy());

        try {
            // Log security event
            logBlacklistRemoval(event);

            Instant processingEnd = clock.instant();
            Duration processingDuration = Duration.between(processingStart, processingEnd);

            log.info("✅ BlacklistRemovedEvent processed at {} in {} - Removed by: {}",
                    processingEnd,
                    processingDuration,
                    event.getRemovedBy());

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to process BlacklistRemovedEvent at {}: {}",
                    errorTime,
                    e.getMessage(),
                    e);

            // Log the failure
            auditLogService.logSystemEvent(
                    "BLACKLIST_EVENT_PROCESSING_FAILURE",
                    "Failed to process blacklist removed event: " + e.getMessage()
            );
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Log blacklist removal to security audit trail
     */
    private void logBlacklistRemoval(BlacklistRemovedEvent event) {
        Instant auditStart = clock.instant();

        try {
            String details = String.format(
                    "IP removed from blacklist at %s by: %s - Reason: %s",
                    event.getTimestamp(),
                    event.getRemovedBy(),
                    event.getReason()
            );

            auditLogService.logSecurityEvent(
                    "BLACKLIST_REMOVED",
                    event.getEncryptedIp(),
                    details
            );

            Instant auditEnd = clock.instant();
            Duration auditDuration = Duration.between(auditStart, auditEnd);

            log.debug("Security audit log created at {} in {} for blacklist removal by: {}",
                    auditEnd,
                    auditDuration,
                    event.getRemovedBy());

        } catch (Exception e) {
            Instant errorTime = clock.instant();

            log.error("❌ Failed to log blacklist removal at {}: {}",
                    errorTime,
                    e.getMessage());
        }
    }
}
