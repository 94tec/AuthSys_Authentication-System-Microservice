package com.techStack.authSys.event;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * Account Locked Event
 *
 * Triggered when a user account is locked due to security reasons.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class AccountLockedEvent extends ApplicationEvent {

    private final String userId;
    private final Instant eventTime;
    private final String reason;
    private final String ipAddress;

    /**
     * Full constructor
     */
    public AccountLockedEvent(
            Object source,
            String userId,
            Instant eventTime,
            String reason,
            String ipAddress) {
        super(source);
        this.userId = userId;
        this.eventTime = eventTime;
        this.reason = reason;
        this.ipAddress = ipAddress;
    }

    /**
     * Simplified constructor with default reason
     */
    public AccountLockedEvent(Object source, String userId, Instant eventTime) {
        this(source, userId, eventTime, "Security policy violation", null);
    }

    /**
     * Convenience constructor with user object as source
     */
    public AccountLockedEvent(String userId, Instant eventTime, String reason, String ipAddress) {
        this(userId, userId, eventTime, reason, ipAddress);
    }

    @Override
    public String toString() {
        return "AccountLockedEvent{" +
                "userId='" + userId + '\'' +
                ", eventTime=" + eventTime +
                ", reason='" + reason + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", parentTimestamp=" + getTimestamp() +  // Spring's timestamp
                '}';
    }
}