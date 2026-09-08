package com.techStack.authSys.auth.event;

import com.techStack.authSys.identity.models.User;
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
    private final Instant eventTimestamp;
    private final String deviceFingerprint;

    public UserRegisteredEvent(
            User user,
            String ipAddress,
            Instant eventTimestamp,
            String deviceFingerprint
            ) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
        this.eventTimestamp = eventTimestamp;
        this.deviceFingerprint = deviceFingerprint;
    }

    // Simplified constructor for backward compatibility
    public UserRegisteredEvent(User user, String ipAddress, Instant eventTimestamp) {
        this(user, ipAddress, eventTimestamp, null);
    }

    @Override
    public String toString() {
        return "UserRegisteredEvent{" +
                "userId='" + user.getId() + '\'' +
                ", email='" + user.getEmail() + '\'' +
                ", status=" + user.getStatus() +
                ", ipAddress='" + ipAddress + '\'' +
                ", eventTimestamp=" + eventTimestamp +
                '}';
    }
}