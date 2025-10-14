package com.techStack.authSys.models;

import java.time.Instant;
import java.util.List;

public class TokenValidationResult {
    private final String subject;
    private final String userId;
    private final String email;
    private final List<String> roles;
    private final List<String> permissions;
    private final Instant expiration;
    private final Instant issuedAt;
    private final boolean valid;
    private final String message;
    private final boolean mfaEnabled;

    public TokenValidationResult(String subject, String userId, String email,
                                 List<String> roles, List<String> permissions,
                                 Instant expiration, Instant issuedAt,
                                 boolean valid, String message,
                                 boolean mfaEnabled) {
        this.subject = subject;
        this.userId = userId;
        this.email = email;
        this.roles = roles != null ? List.copyOf(roles) : List.of();
        this.permissions = permissions != null ? List.copyOf(permissions) : List.of();
        this.expiration = expiration;
        this.issuedAt = issuedAt;
        this.valid = valid;
        this.message = message;
        this.mfaEnabled = mfaEnabled;
    }

    // Getters
    public String getSubject() { return subject; }
    public String getUserId() { return userId; }
    public String getEmail() { return email; }
    public List<String> getRoles() { return roles; }
    public List<String> getPermissions() { return permissions; }
    public Instant getExpiration() { return expiration; }
    public Instant getIssuedAt() { return issuedAt; }
    public boolean isValid() { return valid; }
    public String getMessage() { return message; }
    public boolean isMfaEnabled() { return mfaEnabled; }
}