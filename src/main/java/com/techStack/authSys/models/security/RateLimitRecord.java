package com.techStack.authSys.models.security;

import lombok.Data;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Data
public class RateLimitRecord {
    private String identifier;
    private String type;
    private int minuteCount;
    private int hourCount;
    private int failedAttempts;
    private Instant lastAttempt;
    private Instant blockUntil;

    public RateLimitRecord(String identifier, String type, Instant now) {
        this.identifier = identifier;
        this.type = type;
        this.lastAttempt = now;
    }

    public RateLimitRecord() {
        this.lastAttempt = Instant.now();
    }

    public RateLimitRecord(String identifier) {
        this();
        this.identifier = identifier;
    }

    public void incrementAttempts(Instant now) {
        if (lastAttempt == null || lastAttempt.isBefore(now.minus(1, ChronoUnit.MINUTES))) {
            minuteCount = 0;
        }
        if (lastAttempt == null || lastAttempt.isBefore(now.minus(1, ChronoUnit.HOURS))) {
            hourCount = 0;
        }

        minuteCount++;
        hourCount++;
        failedAttempts++;
        lastAttempt = now;
    }

    public void incrementMinuteCount() {
        if (lastAttempt.isBefore(Instant.now().minus(1, ChronoUnit.MINUTES))) {
            minuteCount = 0;
        }
        minuteCount++;
        lastAttempt = Instant.now();
    }

    public void incrementHourCount() {
        if (lastAttempt.isBefore(Instant.now().minus(1, ChronoUnit.HOURS))) {
            hourCount = 0;
        }
        hourCount++;
        lastAttempt = Instant.now();
    }

    public void resetMinuteCount() {
        this.minuteCount = 0;
    }

    public void resetHourCount() {
        this.hourCount = 0;
    }

    public void incrementFailedAttempts() {
        this.failedAttempts++;
        this.lastAttempt = Instant.now();
    }
}
