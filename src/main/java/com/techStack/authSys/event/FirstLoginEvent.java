package com.techStack.authSys.event;

import com.techStack.authSys.models.user.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * First Login Event
 *
 * Triggered when a user logs in for the first time.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class FirstLoginEvent extends ApplicationEvent {

    private final User user;
    private final String ipAddress;
    private final Instant timestamp;
    private final String deviceFingerprint;

    public FirstLoginEvent(
            User user,
            String ipAddress,
            Instant timestamp,
            String deviceFingerprint) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
        this.deviceFingerprint = deviceFingerprint;
    }

    // Simplified constructor for backward compatibility
    public FirstLoginEvent(User user, String ipAddress, Instant timestamp) {
        this(user, ipAddress, timestamp, null);
    }

    @Override
    public String toString() {
        return "FirstLoginEvent{" +
                "userId='" + user.getId() + '\'' +
                ", email='" + user.getEmail() + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", timestamp=" + timestamp +
                ", deviceFingerprint='" + deviceFingerprint + '\'' +
                '}';
    }
}