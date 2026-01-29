package com.techStack.authSys.models.auth;

import lombok.Builder;

import java.time.Instant;
import java.util.Date;

@Builder
public record TokenClaims(
        String userId,
        String email,
        String ipAddress,
        Date expiration,
        Integer tokenVersion,
        Instant issuedAt
) {

    public boolean isExpired() {
        return expiration.toInstant().isBefore(Instant.now());
    }

    public boolean isValidVersion(int currentVersion) {
        return tokenVersion != null && tokenVersion >= currentVersion;
    }
}
