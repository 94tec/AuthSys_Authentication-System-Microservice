package com.techStack.authSys.models;

import lombok.Data;

import java.time.Instant;

@Data
public class RequestPattern {
    private String userId;
    private String endpoint;
    private int requestCount;
    private long timeWindow; // in minutes
    private Instant lastRequestTime;

    public RequestPattern(String userId, String endpoint, int requestCount, long timeWindow, Instant lastRequestTime) {
        this.userId = userId;
        this.endpoint = endpoint;
        this.requestCount = requestCount;
        this.timeWindow = timeWindow;
        this.lastRequestTime = lastRequestTime;
    }

    public int getNormalThreshold() {
        // Define a reasonable threshold, e.g., 100 requests per time window
        return 100;
    }

    public void incrementCount() {
        this.requestCount++;
    }
}
