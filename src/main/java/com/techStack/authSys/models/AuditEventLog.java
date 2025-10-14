package com.techStack.authSys.models;


import lombok.*;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuditEventLog {
    private String action;
    private String performedBy;
    private String targetUser;
    private Instant timestamp;
    private Map<String, Object> metadata;

    // Constructor, Getters & Setters
    public static AuditEventLog forUserAction(String action, String targetUserId, String performedBy, Map<String, Object> metadata) {
        AuditEventLog event = new AuditEventLog();
        event.setAction(action);
        event.setTargetUser(targetUserId);
        event.setPerformedBy(performedBy);
        event.setMetadata(metadata);
        event.setTimestamp(Instant.now());
        return event;
    }
    public static AuditEventLog forSystemError(String action, String affectedUserId, Map<String, Object> metadata) {
        AuditEventLog event = new AuditEventLog();
        event.setAction(action);
        event.setTargetUser(affectedUserId);
        event.setPerformedBy("SYSTEM"); // or "INTERNAL_SERVICE"
        event.setMetadata(metadata);
        event.setTimestamp(Instant.now());
        return event;
    }

}

