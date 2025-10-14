package com.techStack.authSys.models;

import lombok.Builder;
import lombok.Data;
import java.time.Instant;

@Data
@Builder
public class DeviceInfo {
    private String deviceFingerprint;
    private String userId;
    private String ipAddress;
    private String userAgent;
    private String os;
    private String browser;
    private DeviceTrustLevel trustLevel;
    private Instant registrationDate;
    private Instant lastActive;
    private boolean revoked;
    private String deviceType;
    private Instant createdAt;
    private Instant expiresAt;

    public enum DeviceTrustLevel {
        TRUSTED,           // Fully verified and trusted device
        NEW,               // Recently registered, not yet fully verified
        SUSPICIOUS,        // Shows some suspicious activity
        COMPROMISED        // Known to be compromised
    }

}
