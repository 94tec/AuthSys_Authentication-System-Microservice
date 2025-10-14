package com.techStack.authSys.models;

import com.google.cloud.spring.data.firestore.Document;
import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
@Document(collectionName ="password_change_logs" )
public class AuditLogEntryPasswordChange {
    @Id
    private String id;
    private String eventType;
    private String targetUserId;
    private String actorId;
    private Instant eventTime;
    private String ipAddress;
    private Map<String, Object> metadata;
}
