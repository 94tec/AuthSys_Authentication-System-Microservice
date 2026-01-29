package com.techStack.authSys.models.security;

import lombok.Data;

import java.time.Instant;

@Data
public class RateLimitCache {
    private RateLimitRecord record;
    private Instant blockUntil;
    private Instant expiresAt;

    public RateLimitCache(RateLimitRecord record, Instant expiresAt) {
        this.record = record;
        this.expiresAt = expiresAt;
    }

    public RateLimitCache(Instant blockUntil) {
        this.blockUntil = blockUntil;
        this.expiresAt = blockUntil.plusSeconds(300); // 5 minute cache
    }

    public boolean isBlocked(Instant now) {
        return blockUntil != null && blockUntil.isAfter(now);
    }

    public boolean isExpired(Instant now) {
        return expiresAt != null && expiresAt.isBefore(now);
    }
}
