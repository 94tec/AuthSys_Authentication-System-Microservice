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
    private final Instant timestamp;
    private final String reason;
    private final String ipAddress;

    public AccountLockedEvent(
            Object source,
            String userId,
            Instant timestamp,
            String reason,
            String ipAddress) {
        super(source);
        this.userId = userId;
        this.timestamp = timestamp;
        this.reason = reason;
        this.ipAddress = ipAddress;
    }

    // Simplified constructor
    public AccountLockedEvent(Object source, String userId, Instant timestamp) {
        this(source, userId, timestamp, "Security policy violation", null);
    }

    @Override
    public String toString() {
        return "AccountLockedEvent{" +
                "userId='" + userId + '\'' +
                ", timestamp=" + timestamp +
                ", reason='" + reason + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                '}';
    }
}