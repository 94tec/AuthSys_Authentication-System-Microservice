package com.techStack.authSys.event;

import com.techStack.authSys.models.user.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * Authentication Success Event
 *
 * Triggered when a user successfully authenticates.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class AuthSuccessEvent extends ApplicationEvent {

    private final User user;
    private final String ipAddress;
    private final Instant timestamp;
    private final String deviceFingerprint;
    private final String userAgent;

    public AuthSuccessEvent(
            User user,
            String ipAddress,
            Instant timestamp,
            String deviceFingerprint,
            String userAgent) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
        this.deviceFingerprint = deviceFingerprint;
        this.userAgent = userAgent;
    }

    // Simplified constructor for backward compatibility
    public AuthSuccessEvent(User user, String ipAddress, Instant timestamp) {
        this(user, ipAddress, timestamp, null, null);
    }

    @Override
    public String toString() {
        return "AuthSuccessEvent{" +
                "userId='" + user.getId() + '\'' +
                ", email='" + user.getEmail() + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", timestamp=" + timestamp +
                ", deviceFingerprint='" + deviceFingerprint + '\'' +
                '}';
    }
}