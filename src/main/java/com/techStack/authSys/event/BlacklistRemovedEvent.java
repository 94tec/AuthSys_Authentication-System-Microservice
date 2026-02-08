package com.techStack.authSys.event;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;
import java.util.Objects;

/**
 * Blacklist Removed Event
 *
 * Triggered when an IP address is removed from the blacklist.
 * Uses Clock-based timestamp for consistency.
 */
@Getter
public class BlacklistRemovedEvent extends ApplicationEvent {

    private final String encryptedIp;
    private final Instant eventTimestamp;
    private final String reason;
    private final String removedBy;

    /**
     * Create a new BlacklistRemovedEvent
     *
     * @param source The object on which the event initially occurred
     * @param encryptedIp The encrypted IP address removed from blacklist
     * @param eventTimestamp Event timestamp from Clock
     * @param reason Optional reason for removal
     * @param removedBy Identifier of who initiated the removal
     */
    public BlacklistRemovedEvent(
            Object source,
            String encryptedIp,
            Instant eventTimestamp,
            String reason,
            String removedBy) {
        super(Objects.requireNonNull(source, "Event source cannot be null"));
        this.encryptedIp = Objects.requireNonNull(encryptedIp, "Encrypted IP cannot be null");
        this.eventTimestamp = Objects.requireNonNull(eventTimestamp, "Timestamp cannot be null");
        this.reason = reason;
        this.removedBy = removedBy;
    }

    // Simplified constructor
    public BlacklistRemovedEvent(Object source, String encryptedIp, Instant timestamp) {
        this(source, encryptedIp, timestamp, null, "system");
    }

    @Override
    public String toString() {
        return "BlacklistRemovedEvent{" +
                "encryptedIp='[PROTECTED]'" +
                ", eventTimestamp=" + eventTimestamp +
                ", reason='" + reason + '\'' +
                ", removedBy='" + removedBy + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BlacklistRemovedEvent that = (BlacklistRemovedEvent) o;
        return Objects.equals(encryptedIp, that.encryptedIp) &&
                Objects.equals(eventTimestamp, that.eventTimestamp) &&
                Objects.equals(reason, that.reason) &&
                Objects.equals(removedBy, that.removedBy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptedIp, eventTimestamp, reason, removedBy);
    }
}