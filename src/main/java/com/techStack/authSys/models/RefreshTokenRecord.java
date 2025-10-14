package com.techStack.authSys.models;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.annotation.Exclude;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a refresh token record stored in Firestore
 */
public class RefreshTokenRecord {
    private String tokenId;          // Unique token identifier (JWT ID)
    private String userId;          // User ID this token belongs to
    private String tokenHash;       // Hashed token value (never store raw tokens)
    private String ipAddress;       // IP address where token was issued
    private String userAgent;       // User-Agent header from issuing request
    private Timestamp issuedAt;     // When token was issued
    private Timestamp expiresAt;    // When token expires
    private boolean revoked;        // Whether token was explicitly revoked
    private String revocationReason;// Reason for revocation if applicable
    private String familyId;        // Token family identifier for rotation

    // Firestore requires a no-arg constructor
    public RefreshTokenRecord() {}

    public RefreshTokenRecord(String tokenId,
                              String userId,
                              String tokenHash,
                              String ipAddress,
                              String userAgent,
                              Instant issuedAt,
                              Instant expiresAt,
                              boolean revoked) {
        this(tokenId, userId, tokenHash, ipAddress, userAgent,
                issuedAt, expiresAt, revoked, null, UUID.randomUUID().toString());
    }

    public RefreshTokenRecord(String tokenId,
                              String userId,
                              String tokenHash,
                              String ipAddress,
                              String userAgent,
                              Instant issuedAt,
                              Instant expiresAt,
                              boolean revoked,
                              String revocationReason,
                              String familyId) {
        Assert.hasText(tokenId, "Token ID cannot be empty");
        Assert.hasText(userId, "User ID cannot be empty");
        Assert.hasText(tokenHash, "Token hash cannot be empty");

        this.tokenId = tokenId;
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.issuedAt = Timestamp.ofTimeSecondsAndNanos(issuedAt.getEpochSecond(), issuedAt.getNano());
        this.expiresAt = Timestamp.ofTimeSecondsAndNanos(expiresAt.getEpochSecond(), expiresAt.getNano());
        this.revoked = revoked;
        this.revocationReason = revocationReason;
        this.familyId = familyId;
    }

    // ========== Firestore Serialization Helpers ==========

    public static RefreshTokenRecord fromMap(Map<String, Object> map) {
        RefreshTokenRecord record = new RefreshTokenRecord();
        record.tokenId = (String) map.get("tokenId");
        record.userId = (String) map.get("userId");
        record.tokenHash = (String) map.get("tokenHash");
        record.ipAddress = (String) map.get("ipAddress");
        record.userAgent = (String) map.get("userAgent");
        record.issuedAt = (Timestamp) map.get("issuedAt");
        record.expiresAt = (Timestamp) map.get("expiresAt");
        record.revoked = (boolean) map.get("revoked");
        record.revocationReason = (String) map.get("revocationReason");
        record.familyId = (String) map.get("familyId");
        return record;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("tokenId", tokenId);
        map.put("userId", userId);
        map.put("tokenHash", tokenHash);
        map.put("ipAddress", ipAddress);
        map.put("userAgent", userAgent);
        map.put("issuedAt", issuedAt);
        map.put("expiresAt", expiresAt);
        map.put("revoked", revoked);
        map.put("revocationReason", revocationReason);
        map.put("familyId", familyId);
        return map;
    }

    // ========== Business Logic Methods ==========

    @Exclude
    public boolean isActive() {
        return !revoked && !isExpired();
    }

    @Exclude
    public boolean isExpired() {
        return Instant.now().isAfter(getExpiresAtInstant());
    }

    @Exclude
    public void revoke(String reason) {
        this.revoked = true;
        this.revocationReason = reason;
    }

    // ========== Getters and Setters ==========
    public String getTokenId() {
        return tokenId;
    }

    public String getUserId() {
        return userId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    @Exclude
    public Instant getIssuedAtInstant() {
        return issuedAt.toSqlTimestamp().toInstant();
    }

    public Timestamp getIssuedAt() {
        return issuedAt;
    }

    @Exclude
    public Instant getExpiresAtInstant() {
        return expiresAt.toSqlTimestamp().toInstant();
    }

    public Timestamp getExpiresAt() {
        return expiresAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public String getFamilyId() {
        return familyId;
    }

    // ... setters omitted for brevity

    // ========== Equals/HashCode/ToString ==========
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RefreshTokenRecord that = (RefreshTokenRecord) o;
        return tokenId.equals(that.tokenId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenId);
    }

    @Override
    public String toString() {
        return STR."RefreshTokenRecord{tokenId='\{tokenId}', userId='\{userId}', ipAddress='\{ipAddress}', issuedAt=\{issuedAt}, expiresAt=\{expiresAt}, revoked=\{revoked}}";
    }
}
