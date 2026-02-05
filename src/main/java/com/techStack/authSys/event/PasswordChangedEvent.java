package com.techStack.authSys.event;

import com.techStack.authSys.models.user.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * Password Changed Event
 *
 * Triggered when a user's password is changed.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class PasswordChangedEvent extends ApplicationEvent {

    private final User user;
    private final String ipAddress;
    private final Instant timestamp;
    private final boolean forced; // true if admin-forced, false if user-initiated

    public PasswordChangedEvent(
            User user,
            String ipAddress,
            Instant timestamp,
            boolean forced) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
        this.forced = forced;
    }

    // Simplified constructor for user-initiated changes
    public PasswordChangedEvent(User user, String ipAddress, Instant timestamp) {
        this(user, ipAddress, timestamp, false);
    }

    @Override
    public String toString() {
        return "PasswordChangedEvent{" +
                "userId='" + user.getId() + '\'' +
                ", email='" + user.getEmail() + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", timestamp=" + timestamp +
                ", forced=" + forced +
                '}';
    }
}
