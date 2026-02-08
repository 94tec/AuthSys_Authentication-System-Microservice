package com.techStack.authSys.event;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * User Rejected Event
 *
 * Triggered when a pending user is rejected by an admin.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class UserRejectedEvent extends ApplicationEvent {

    private final String userId;
    private final String email;
    private final String rejectedBy;
    private final String rejectorRole;
    private final String reason;

    // ✅ Rename this to avoid clashing with ApplicationEvent.getTimestamp()
    private final Instant occurredAt;

    public UserRejectedEvent(
            Object source,
            String userId,
            String email,
            String rejectedBy,
            String rejectorRole,
            String reason,
            Instant occurredAt
    ) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.rejectedBy = rejectedBy;
        this.rejectorRole = rejectorRole;
        this.reason = reason;
        this.occurredAt = occurredAt;
    }

    @Override
    public String toString() {
        return "UserRejectedEvent{" +
                "userId='" + userId + '\'' +
                ", email='" + email + '\'' +
                ", rejectedBy='" + rejectedBy + '\'' +
                ", rejectorRole='" + rejectorRole + '\'' +
                ", reason='" + reason + '\'' +
                ", occurredAt=" + occurredAt +
                '}';
    }
}
