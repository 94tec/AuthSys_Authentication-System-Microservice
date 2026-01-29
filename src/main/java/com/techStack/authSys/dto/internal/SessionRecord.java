package com.techStack.authSys.dto.internal;

import com.google.cloud.Timestamp;
import com.techStack.authSys.models.session.SessionStatus;
import lombok.Data;

@Data
public class SessionRecord {
    private String sessionId;
    private String userId;
    private String ipAddress;
    private String device;
    private SessionStatus status;
    private Timestamp loginTime;
    private Timestamp lastSeen;

}

