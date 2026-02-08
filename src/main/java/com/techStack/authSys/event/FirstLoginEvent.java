package com.techStack.authSys.event;

import com.techStack.authSys.models.user.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;
import java.util.Set;

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
    private final Instant eventTimestamp;
    private final String deviceFingerprint;

    public FirstLoginEvent(
            User user,
            String ipAddress,
            Instant eventTimestamp,
            String deviceFingerprint) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
        this.eventTimestamp = eventTimestamp;
        this.deviceFingerprint = deviceFingerprint;
    }

    // Simplified constructor for backward compatibility
    public FirstLoginEvent(User user, String ipAddress, Instant eventTimestamp) {
        this(user, ipAddress, eventTimestamp, null);
    }

    @Override
    public String toString() {
        return "FirstLoginEvent{" +
                "userId='" + user.getId() + '\'' +
                ", email='" + user.getEmail() + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", eventTimestamp=" + eventTimestamp +
                ", deviceFingerprint='" + deviceFingerprint + '\'' +
                '}';
    }
}