package com.techStack.authSys.dto.response;

import com.techStack.authSys.models.audit.ActionType;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
public class AuditLogDTO {
    private String id; // Firestore uses String IDs instead of UUID
    private String userId; // Firestore does not support direct entity relationships
    private Date createdAt;
    private ActionType actionType;
    private String ipAddress;
    private String details;
}
