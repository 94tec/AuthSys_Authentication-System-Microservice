package com.techStack.authSys.security.audit;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
public class AuditLogDTO {
    private String id;
    private String userId;
    private String userEmail;
    private Date createdAt;
    private ActionType actionType;
    private String action;
    private String severity;
    private String ipAddress;
    private String details;
    private String entityType;
    private String entityId;
    private Instant timestamp;
}