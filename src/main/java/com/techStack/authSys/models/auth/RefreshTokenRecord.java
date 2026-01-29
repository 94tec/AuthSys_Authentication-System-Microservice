package com.techStack.authSys.models.auth;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.annotation.Exclude;
import lombok.Builder;
import lombok.NoArgsConstructor;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a refresh token record stored in Firestore
 */
@NoArgsConstructor // Firestore requires this
public class RefreshTokenRecord {

    private String tokenId;
    private String userId;
    private String tokenHash;
    private String ipAddress;
    private String userAgent;

    private Timestamp issuedAt;
    private Timestamp expiresAt;

    private boolean revoked;
    private String revocationReason;
    private String familyId;

    @Builder
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

        this.issuedAt = Timestamp.ofTimeSecondsAndNanos(
                issuedAt.getEpochSecond(),
                issuedAt.getNano()
        );

        this.expiresAt = Timestamp.ofTimeSecondsAndNanos(
                expiresAt.getEpochSecond(),
                expiresAt.getNano()
        );

        this.revoked = revoked;
        this.revocationReason = revocationReason;
        this.familyId = (familyId != null) ? familyId : UUID.randomUUID().toString();
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

        record.revoked = (boolean) map.getOrDefault("revoked", false);
        record.revocationReason = (String) map.get("revocationReason");
        record.familyId = (String) map.getOrDefault("familyId", UUID.randomUUID().toString());

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

    // ========== Getters ==========
    public String getTokenId() { return tokenId; }
    public String getUserId() { return userId; }
    public String getTokenHash() { return tokenHash; }
    public String getIpAddress() { return ipAddress; }
    public String getUserAgent() { return userAgent; }

    public Timestamp getIssuedAt() { return issuedAt; }
    public Timestamp getExpiresAt() { return expiresAt; }

    @Exclude
    public Instant getIssuedAtInstant() {
        return issuedAt.toSqlTimestamp().toInstant();
    }

    @Exclude
    public Instant getExpiresAtInstant() {
        return expiresAt.toSqlTimestamp().toInstant();
    }

    public boolean isRevoked() { return revoked; }
    public String getRevocationReason() { return revocationReason; }
    public String getFamilyId() { return familyId; }

    // ========== Equals/HashCode/ToString ==========

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshTokenRecord that)) return false;
        return tokenId.equals(that.tokenId);
    }

    @Override
    public int hashCode() { return Objects.hash(tokenId); }

    @Override
    public String toString() {
        return STR."RefreshTokenRecord{tokenId='\{tokenId}', userId='\{userId}', expiresAt=\{expiresAt}, revoked=\{revoked}}";
    }
}
