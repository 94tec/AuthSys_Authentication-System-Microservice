package com.techStack.authSys.models.security;

import lombok.*;
import org.jetbrains.annotations.NotNull;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Security Metadata
 *
 * Modularized security tracking with inner utility classes.
 * All methods accept Instant for timestamps.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityMetadata {

    /* =========================
       Core Fields
       ========================= */
    @Builder.Default
    private int failedLoginAttempts = 0;
    private Instant lastFailedLoginAt;
    private Instant lastSuccessfulLoginAt;
    private Instant failedAttemptsResetAt;

    private Instant passwordLastChangedAt;
    @Builder.Default
    private boolean passwordCompromised = false;
    private String compromiseSource;

    @Builder.Default
    private Set<String> knownDeviceFingerprints = new LinkedHashSet<>();
    private String lastLoginDeviceId;
    private String lastLoginUserAgent;

    private String lastLoginCountry;
    private String lastLoginCity;
    private String lastLoginIp;
    private Instant lastLoginAt;

    private Instant accountLockedUntil;
    private String lockReason;
    private LockType lockType;

    @Builder.Default
    private int riskScore = 0;
    private Instant riskScoreUpdatedAt;
    private String riskExplanation;
    private RiskLevel riskLevel;

    @Builder.Default
    private boolean mfaEnabled = false;
    private String mfaMethod;
    private Instant lastMfaVerifiedAt;

    /* =========================
       Accessor Methods
       ========================= */

    public Locking locking() {
        return new Locking();
    }

    public LoginTracking login() {
        return new LoginTracking();
    }

    public Device device() {
        return new Device();
    }

    public Risk risk() {
        return new Risk();
    }

    public Password password() {
        return new Password();
    }

    public Location location() {
        return new Location();
    }

    /* =========================
       Inner Utility Classes
       ========================= */

    public class Locking {
        public boolean isTemporarilyLocked(@NotNull Instant now) {
            return accountLockedUntil != null && now.isBefore(accountLockedUntil);
        }

        public void apply(
                @NotNull Instant now,
                @NotNull Duration duration,
                @NotNull String reason,
                @NotNull LockType type
        ) {
            accountLockedUntil = now.plus(duration);
            lockReason = reason;
            lockType = type;
        }

        public void release() {
            accountLockedUntil = null;
            lockReason = null;
            lockType = null;
        }

        public Optional<Duration> remaining(@NotNull Instant now) {
            if (!isTemporarilyLocked(now)) return Optional.empty();
            return Optional.of(Duration.between(now, accountLockedUntil));
        }
    }

    public class LoginTracking {
        public void recordFailed(@NotNull Instant now) {
            failedLoginAttempts++;
            lastFailedLoginAt = now;
        }

        public void recordSuccess(
                @NotNull Instant now,
                @NotNull String ip,
                String deviceId,
                String country,
                String city
        ) {
            lastSuccessfulLoginAt = now;
            lastLoginAt = now;
            lastLoginIp = ip;
            lastLoginDeviceId = deviceId;
            lastLoginCountry = country;
            lastLoginCity = city;
            resetFailures(now);
        }

        public void resetFailures(@NotNull Instant now) {
            failedLoginAttempts = 0;
            failedAttemptsResetAt = now;
        }

        public boolean exceededThreshold(int threshold) {
            return failedLoginAttempts >= threshold;
        }
    }

    public class Device {
        public void register(@NotNull String fingerprint, int maxDevices) {
            knownDeviceFingerprints.add(fingerprint);
            while (knownDeviceFingerprints.size() > maxDevices) {
                knownDeviceFingerprints.iterator().remove();
            }
        }

        public boolean isKnown(@NotNull String fingerprint) {
            return knownDeviceFingerprints.contains(fingerprint);
        }

        public boolean remove(@NotNull String fingerprint) {
            return knownDeviceFingerprints.remove(fingerprint);
        }

        public void clearAll() {
            knownDeviceFingerprints.clear();
        }
    }

    public class Risk {
        public boolean isHigh() {
            return riskScore >= 70;
        }

        public boolean isMedium() {
            return riskScore >= 40 && riskScore < 70;
        }

        public boolean isLow() {
            return riskScore < 40;
        }

        public void update(@NotNull Instant now, int newScore, String explanation) {
            if (newScore < 0 || newScore > 100) {
                throw new IllegalArgumentException("Risk score must be 0-100");
            }
            riskScore = newScore;
            riskScoreUpdatedAt = now;
            riskExplanation = explanation;
            riskLevel = RiskLevel.fromScore(newScore);
        }

        public boolean isStale(@NotNull Instant now, @NotNull Duration maxAge) {
            if (riskScoreUpdatedAt == null) return true;
            Instant staleThreshold = now.minus(maxAge);
            return riskScoreUpdatedAt.isBefore(staleThreshold);
        }
    }

    public class Password {
        public void markCompromised(@NotNull String source) {
            passwordCompromised = true;
            compromiseSource = source;
        }

        public void clearCompromise() {
            passwordCompromised = false;
            compromiseSource = null;
        }

        public void recordChange(@NotNull Instant now) {
            passwordLastChangedAt = now;
            clearCompromise();
        }

        public boolean isChangeOverdue(@NotNull Instant now, @NotNull Duration maxAge) {
            if (passwordLastChangedAt == null) return true;
            Instant threshold = now.minus(maxAge);
            return passwordLastChangedAt.isBefore(threshold);
        }
    }

    public class Location {
        public boolean hasChanged(String newCountry, String newCity) {
            if (lastLoginCountry == null) return true;
            boolean countryChanged = !lastLoginCountry.equals(newCountry);
            boolean cityChanged = lastLoginCity != null &&
                    newCity != null &&
                    !lastLoginCity.equals(newCity);
            return countryChanged || cityChanged;
        }
    }

    /* =========================
       Enums
       ========================= */

    public enum LockType {
        BRUTE_FORCE("Brute Force Protection", "Account locked due to multiple failed login attempts"),
        SUSPICIOUS_ACTIVITY("Suspicious Activity", "Account locked due to suspicious behavior"),
        LOCATION_ANOMALY("Location Anomaly", "Account locked due to unusual login location"),
        DEVICE_ANOMALY("Device Anomaly", "Account locked due to unrecognized device"),
        MANUAL("Manual Lock", "Account manually locked by administrator");

        private final String displayName;
        private final String description;

        LockType(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getDescription() {
            return description;
        }

        @Override
        public String toString() {
            return name() + " (" + displayName + ")";
        }
    }

    public enum RiskLevel {
        LOW("Low Risk", 0, 39),
        MEDIUM("Medium Risk", 40, 69),
        HIGH("High Risk", 70, 89),
        CRITICAL("Critical Risk", 90, 100);

        private final String displayName;
        private final int minScore;
        private final int maxScore;

        RiskLevel(String displayName, int minScore, int maxScore) {
            this.displayName = displayName;
            this.minScore = minScore;
            this.maxScore = maxScore;
        }

        public String getDisplayName() {
            return displayName;
        }

        public static RiskLevel fromScore(int score) {
            for (RiskLevel level : values()) {
                if (score >= level.minScore && score <= level.maxScore) {
                    return level;
                }
            }
            return LOW;
        }

        @Override
        public String toString() {
            return name() + " (" + displayName + ")";
        }
    }
}