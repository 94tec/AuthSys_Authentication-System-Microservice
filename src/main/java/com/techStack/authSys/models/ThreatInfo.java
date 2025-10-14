package com.techStack.authSys.models;

import java.time.Instant;

public class ThreatInfo {
    private boolean isThreat;
    private String threatKey;
    private Instant detectedAt;
    private String reason;

    // Full Constructor
    public ThreatInfo(boolean isThreat, String threatKey, Instant detectedAt, String reason) {
        this.isThreat = isThreat;
        this.threatKey = threatKey;
        this.detectedAt = detectedAt;
        this.reason = reason;
    }

    // Constructor for minimal initialization
    public ThreatInfo(String threatKey) {
        this.threatKey = threatKey;
        this.isThreat = false;  // Default value
        this.detectedAt = Instant.now();  // Default to current time
        this.reason = "Unknown";  // Default reason
    }

    // Getters
    public boolean isThreat() { return isThreat; }
    public String getThreatKey() { return threatKey; }
    public Instant getDetectedAt() { return detectedAt; }
    public String getReason() { return reason; }

    // Setters
    public void setThreat(boolean threat) { isThreat = threat; }
    public void setThreatKey(String threatKey) { this.threatKey = threatKey; }
    public void setDetectedAt(Instant detectedAt) { this.detectedAt = detectedAt; }
    public void setReason(String reason) { this.reason = reason; }

    @Override
    public String toString() {
        return "ThreatInfo{" +
                "isThreat=" + isThreat +
                ", threatKey='" + threatKey + '\'' +
                ", detectedAt=" + detectedAt +
                ", reason='" + reason + '\'' +
                '}';
    }
}
