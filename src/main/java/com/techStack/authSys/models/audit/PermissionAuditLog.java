package com.techStack.authSys.models.audit;

import com.google.cloud.spring.data.firestore.Document;
import lombok.Data;
import org.springframework.data.annotation.Id;


import java.time.Instant;

@Data
@Document(collectionName = "permission_audit_logs")
public class PermissionAuditLog {
    @Id
    private String id;

    private String userId;
    private String action;      // e.g., "ATTEMPTED_ACCESS"
    private String resource;
    private Instant timestamp;
    private boolean allowed;

    private String contextJson; // Additional context or request metadata
}
