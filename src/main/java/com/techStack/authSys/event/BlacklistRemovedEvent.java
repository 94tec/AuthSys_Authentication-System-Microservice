package com.techStack.authSys.event;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;
import java.util.Objects;

/**
 * Event triggered when an IP address is removed from the blacklist.
 * Contains the encrypted IP address that was removed for security purposes.
 */
public class BlacklistRemovedEvent extends ApplicationEvent {
    @Getter
    private final String encryptedIp;
    private final long timestamp;
    @Getter
    private final String reason;  // Optional reason for removal
    @Getter
    private final String removedBy;  // Who initiated the removal

    /**
     * Creates a new BlacklistRemovedEvent.
     *
     * @param source The object on which the event initially occurred (never {@code null})
     * @param encryptedIp The encrypted IP address that was removed from the blacklist
     * @param reason Optional reason for the removal (can be null)
     * @param removedBy Identifier of who initiated the removal
     * @throws IllegalArgumentException if source or encryptedIp is null
     */
    public BlacklistRemovedEvent(Object source,
                                 String encryptedIp,
                                 String reason,
                                 String removedBy) {
        super(Objects.requireNonNull(source, "Event source cannot be null"));
        this.encryptedIp = Objects.requireNonNull(encryptedIp, "Encrypted IP cannot be null");
        this.timestamp = System.currentTimeMillis();
        this.reason = reason;
        this.removedBy = removedBy;
    }

    // Simplified constructor
    public BlacklistRemovedEvent(Object source, String encryptedIp) {
        this(source, encryptedIp, null, "system");
    }

    @Override
    public String toString() {
        return "BlacklistRemovedEvent{" +
                "source=" + source +
                ", encryptedIp='[PROTECTED]'" +
                ", timestamp=" + timestamp +
                ", reason='" + reason + '\'' +
                ", removedBy='" + removedBy + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BlacklistRemovedEvent that = (BlacklistRemovedEvent) o;
        return timestamp == that.timestamp &&
                Objects.equals(encryptedIp, that.encryptedIp) &&
                Objects.equals(reason, that.reason) &&
                Objects.equals(removedBy, that.removedBy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptedIp, timestamp, reason, removedBy);
    }
}