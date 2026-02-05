package com.techStack.authSys.service.events;

import com.techStack.authSys.event.*;
import com.techStack.authSys.models.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;

/**
 * Event Publisher Service
 *
 * Centralized service for publishing application events with Clock-based timestamps.
 * All events use Clock for consistent timestamp tracking.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EventPublisherService {

    /* =========================
       Dependencies
       ========================= */

    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

    /* =========================
       Authentication Events
       ========================= */

    /**
     * Publish authentication success event
     */
    public void publishAuthSuccess(
            User user,
            String ipAddress,
            String deviceFingerprint,
            String userAgent) {

        Instant now = clock.instant();

        AuthSuccessEvent event = new AuthSuccessEvent(
                user,
                ipAddress,
                now,
                deviceFingerprint,
                userAgent
        );

        eventPublisher.publishEvent(event);

        log.debug("Published AuthSuccessEvent at {} for user: {}", now, user.getId());
    }

    /* =========================
       Registration Events
       ========================= */

    /**
     * Publish user registered event
     */
    public void publishUserRegistered(
            User user,
            String ipAddress,
            String deviceFingerprint,
            Set<String> requestedRoles) {

        Instant now = clock.instant();

        UserRegisteredEvent event = new UserRegisteredEvent(
                user,
                ipAddress,
                now,
                deviceFingerprint,
                requestedRoles
        );

        eventPublisher.publishEvent(event);

        log.debug("Published UserRegisteredEvent at {} for user: {}", now, user.getId());
    }

    /* =========================
       Login Events
       ========================= */

    /**
     * Publish first login event
     */
    public void publishFirstLogin(
            User user,
            String ipAddress,
            String deviceFingerprint) {

        Instant now = clock.instant();

        FirstLoginEvent event = new FirstLoginEvent(
                user,
                ipAddress,
                now,
                deviceFingerprint
        );

        eventPublisher.publishEvent(event);

        log.debug("Published FirstLoginEvent at {} for user: {}", now, user.getId());
    }

    /* =========================
       Account Events
       ========================= */

    /**
     * Publish account locked event
     */
    public void publishAccountLocked(
            String userId,
            String reason,
            String ipAddress) {

        Instant now = clock.instant();

        AccountLockedEvent event = new AccountLockedEvent(
                this,
                userId,
                now,
                reason,
                ipAddress
        );

        eventPublisher.publishEvent(event);

        log.warn("Published AccountLockedEvent at {} for user: {} - Reason: {}",
                now, userId, reason);
    }

    /* =========================
       Password Events
       ========================= */

    /**
     * Publish password changed event
     */
    public void publishPasswordChanged(
            User user,
            String ipAddress,
            boolean forced) {

        Instant now = clock.instant();

        PasswordChangedEvent event = new PasswordChangedEvent(
                user,
                ipAddress,
                now,
                forced
        );

        eventPublisher.publishEvent(event);

        log.info("Published PasswordChangedEvent at {} for user: {} (forced: {})",
                now, user.getId(), forced);
    }

    /* =========================
       Email Verification Events
       ========================= */

    /**
     * Publish email verified event
     */
    public void publishEmailVerified(
            String userId,
            String email,
            String ipAddress) {

        Instant now = clock.instant();

        EmailVerifiedEvent event = new EmailVerifiedEvent(
                this,
                userId,
                email,
                now,
                ipAddress
        );

        eventPublisher.publishEvent(event);

        log.info("Published EmailVerifiedEvent at {} for user: {}", now, userId);
    }

    /* =========================
       Approval Events
       ========================= */

    /**
     * Publish user approved event
     */
    public void publishUserApproved(
            User user,
            String approvedBy,
            String approverRole) {

        Instant now = clock.instant();

        UserApprovedEvent event = new UserApprovedEvent(
                user,
                approvedBy,
                approverRole,
                now
        );

        eventPublisher.publishEvent(event);

        log.info("Published UserApprovedEvent at {} for user: {} approved by: {}",
                now, user.getId(), approvedBy);
    }

    /**
     * Publish user rejected event
     */
    public void publishUserRejected(
            String userId,
            String email,
            String rejectedBy,
            String rejectorRole,
            String reason) {

        Instant now = clock.instant();

        UserRejectedEvent event = new UserRejectedEvent(
                this,
                userId,
                email,
                rejectedBy,
                rejectorRole,
                reason,
                now
        );

        eventPublisher.publishEvent(event);

        log.warn("Published UserRejectedEvent at {} for user: {} rejected by: {} - Reason: {}",
                now, userId, rejectedBy, reason);
    }

    /* =========================
       Security Events
       ========================= */

    /**
     * Publish blacklist removed event
     */
    public void publishBlacklistRemoved(
            String encryptedIp,
            String reason,
            String removedBy) {

        Instant now = clock.instant();

        BlacklistRemovedEvent event = new BlacklistRemovedEvent(
                this,
                encryptedIp,
                now,
                reason,
                removedBy
        );

        eventPublisher.publishEvent(event);

        log.info("Published BlacklistRemovedEvent at {} - Removed by: {}",
                now, removedBy);
    }
}