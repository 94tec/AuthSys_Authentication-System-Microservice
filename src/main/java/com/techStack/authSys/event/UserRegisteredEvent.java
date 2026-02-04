package com.techStack.authSys.event;

import com.techStack.authSys.models.user.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;
import java.util.Set;

/**
 * User Registered Event
 *
 * Triggered when a new user completes registration.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class UserRegisteredEvent extends ApplicationEvent {

    private final User user;
    private final String ipAddress;
    private final Instant timestamp;
    private final String deviceFingerprint;
    private final Set<String> requestedRoles;

    public UserRegisteredEvent(
            User user,
            String ipAddress,
            Instant timestamp,
            String deviceFingerprint,
            Set<String> requestedRoles) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
        this.deviceFingerprint = deviceFingerprint;
        this.requestedRoles = requestedRoles;
    }

    // Simplified constructor for backward compatibility
    public UserRegisteredEvent(User user, String ipAddress, Instant timestamp) {
        this(user, ipAddress, timestamp, null, null);
    }

    @Override
    public String toString() {
        return "UserRegisteredEvent{" +
                "userId='" + user.getId() + '\'' +
                ", email='" + user.getEmail() + '\'' +
                ", status=" + user.getStatus() +
                ", ipAddress='" + ipAddress + '\'' +
                ", timestamp=" + timestamp +
                ", requestedRoles=" + requestedRoles +
                '}';
    }
}