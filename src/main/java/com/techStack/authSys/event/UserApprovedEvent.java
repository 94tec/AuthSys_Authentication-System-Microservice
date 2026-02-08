package com.techStack.authSys.event;

import com.techStack.authSys.models.user.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * User Approved Event
 *
 * Triggered when a pending user is approved by an admin.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class UserApprovedEvent extends ApplicationEvent {

    private final User user;
    private final String approvedBy;
    private final String approverRole;
    private final Instant eventTimestamp;

    public UserApprovedEvent(
            User user,
            String approvedBy,
            String approverRole,
            Instant eventTimestamp) {
        super(user);
        this.user = user;
        this.approvedBy = approvedBy;
        this.approverRole = approverRole;
        this.eventTimestamp = eventTimestamp;
    }

    @Override
    public String toString() {
        return "UserApprovedEvent{" +
                "userId='" + user.getId() + '\'' +
                ", email='" + user.getEmail() + '\'' +
                ", approvedBy='" + approvedBy + '\'' +
                ", approverRole='" + approverRole + '\'' +
                ", eventTimestamp=" + eventTimestamp +
                '}';
    }
}
