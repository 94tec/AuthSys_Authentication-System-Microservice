package com.techStack.authSys.auth.dto;

import com.google.cloud.Timestamp;
import com.techStack.authSys.auth.model.SessionStatus;
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

