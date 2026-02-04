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
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EventPublisherService {

    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

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
