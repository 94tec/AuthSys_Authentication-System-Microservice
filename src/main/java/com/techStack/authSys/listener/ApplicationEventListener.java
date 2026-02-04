package com.techStack.authSys.listener;

import com.techStack.authSys.event.*;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.notification.EmailService;
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
 * Application Event Listener
 *
 * Central listener for all application events.
 * Uses Clock for timestamp tracking and comprehensive audit logging.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApplicationEventListener {

    /* =========================
       Dependencies
       ========================= */

    private final AuditLogService auditLogService;
    private final EmailService emailService;
    private final Clock clock;

    /* =========================
       Authentication Events
       ========================= */

    /**
     * Handle authentication success event
     */
    @Async
    @EventListener
    public void handleAuthSuccess(AuthSuccessEvent event) {
        Instant processingTime = clock.instant();

        log.info("Processing AuthSuccessEvent at {} (event time: {}) for user: {}",
                processingTime,
                event.getTimestamp(),
                HelperUtils.maskEmail(event.getUser().getEmail()));

        try {
            auditLogService.logLoginAttempt(
                    event.getUser().getEmail(),
                    event.getIpAddress(),
                    true
            );

            log.debug("✅ Auth success logged at {} for user: {}",
                    clock.instant(),
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            log.error("❌ Failed to process auth success event at {}: {}",
                    clock.instant(), e.getMessage(), e);
        }
    }

    /* =========================
       Registration Events
       ========================= */

    /**
     * Handle user registered event
     */
    @Async
    @EventListener
    public void handleUserRegistered(UserRegisteredEvent event) {
        Instant processingTime = clock.instant();

        log.info("Processing UserRegisteredEvent at {} (event time: {}) for user: {}",
                processingTime,
                event.getTimestamp(),
                HelperUtils.maskEmail(event.getUser().getEmail()));

        try {
            auditLogService.logRegistrationSuccess(
                    event.getUser().getEmail(),
                    event.getUser().getRoles(),
                    event.getUser().getStatus(),
                    event.getIpAddress()
            );

            log.debug("✅ Registration logged at {} for user: {}",
                    clock.instant(),
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            log.error("❌ Failed to process registration event at {}: {}",
                    clock.instant(), e.getMessage(), e);
        }
    }

    /* =========================
       First Login Events
       ========================= */

    /**
     * Handle first login event
     */
    @Async
    @EventListener
    public void handleFirstLogin(FirstLoginEvent event) {
        Instant processingTime = clock.instant();

        log.info("Processing FirstLoginEvent at {} (event time: {}) for user: {}",
                processingTime,
                event.getTimestamp(),
                HelperUtils.maskEmail(event.getUser().getEmail()));

        try {
            // Send first login notification email
            emailService.sendFirstLoginNotification(
                    event.getUser().getEmail(),
                    event.getIpAddress(),
                    event.getTimestamp()
            );

            // Log the first login
            auditLogService.logUserEvent(
                    event.getUser(),
                    ActionType.FIRST_LOGIN,
                    "First login from IP: " + event.getIpAddress() +
                            " at " + event.getTimestamp(),
                    event.getIpAddress()
            );

            log.info("✅ First login processed at {} for user: {}",
                    clock.instant(),
                    HelperUtils.maskEmail(event.getUser().getEmail()));

        } catch (Exception e) {
            log.error("❌ Failed to process first login event at {}: {}",
                    clock.instant(), e.getMessage(), e);
        }
    }

    /* =========================
       Account Lock Events
       ========================= */

    /**
     * Handle account locked event
     */
    @Async
    @EventListener
    public void handleAccountLocked(AccountLockedEvent event) {
        Instant processingTime = clock.instant();

        log.warn("Processing AccountLockedEvent at {} (event time: {}) for user: {}",
                processingTime,
                event.getTimestamp(),
                event.getUserId());

        try {
            // Log security event
            auditLogService.logSecurityEvent(
                    "ACCOUNT_LOCKED",
                    event.getUserId(),
                    "Account locked at " + event.getTimestamp() +
                            " - Reason: " + event.getReason() +
                            " - IP: " + event.getIpAddress()
            );

            // Send account locked notification email
            emailService.sendAccountLockedNotification(
                    event.getUserId(),
                    event.getReason(),
                    event.getTimestamp()
            );

            log.warn("✅ Account lock processed at {} for user: {}",
                    clock.instant(),
                    event.getUserId());

        } catch (Exception e) {
            log.error("❌ Failed to process account locked event at {}: {}",
                    clock.instant(), e.getMessage(), e);
        }
    }

    /* =========================
       Blacklist Events
       ========================= */

    /**
     * Handle blacklist removed event
     */
    @Async
    @EventListener
    public void handleBlacklistRemoved(BlacklistRemovedEvent event) {
        Instant processingTime = clock.instant();

        log.info("Processing BlacklistRemovedEvent at {} (event time: {})",
                processingTime,
                event.getTimestamp());

        try {
            auditLogService.logSecurityEvent(
                    "BLACKLIST_REMOVED",
                    event.getEncryptedIp(),
                    "IP removed from blacklist at " + event.getTimestamp() +
                            " by: " + event.getRemovedBy() +
                            " - Reason: " + event.getReason()
            );

            log.info("✅ Blacklist removal logged at {} - Removed by: {}",
                    clock.instant(),
                    event.getRemovedBy());

        } catch (Exception e) {
            log.error("❌ Failed to process blacklist removed event at {}: {}",
                    clock.instant(), e.getMessage(), e);
        }
    }

    /* =========================
       Performance Monitoring
       ========================= */

    /**
     * Log event processing duration for monitoring
     */
    private void logEventProcessingDuration(
            String eventType,
            Instant startTime,
            String userIdentifier) {

        Instant endTime = clock.instant();
        Duration duration = Duration.between(startTime, endTime);

        if (duration.toMillis() > 1000) {
            log.warn("⚠️ Slow event processing: {} took {} for {}",
                    eventType,
                    duration,
                    userIdentifier);
        } else {
            log.debug("Event processing: {} completed in {} for {}",
                    eventType,
                    duration,
                    userIdentifier);
        }
    }
}