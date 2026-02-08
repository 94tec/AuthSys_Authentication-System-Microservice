package com.techStack.authSys.event;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * Email Verified Event
 *
 * Triggered when a user verifies their email address.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class EmailVerifiedEvent extends ApplicationEvent {

    private final String userId;
    private final String email;

    // ✅ DO NOT name it "timestamp"
    private final Instant occurredAt;

    private final String ipAddress;

    public EmailVerifiedEvent(
            Object source,
            String userId,
            String email,
            Instant occurredAt,
            String ipAddress
    ) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.occurredAt = occurredAt;
        this.ipAddress = ipAddress;
    }

    @Override
    public String toString() {
        return "EmailVerifiedEvent{" +
                "userId='" + userId + '\'' +
                ", email='" + email + '\'' +
                ", occurredAt=" + occurredAt +
                ", ipAddress='" + ipAddress + '\'' +
                '}';
    }
}
