package com.techStack.authSys.models.security;

import lombok.*;
import org.jetbrains.annotations.NotNull;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Security Metadata
 *
 * Holds security-related telemetry and risk signals.
 * Not authoritative for authentication decisions on its own.
 * Used for fraud detection, risk assessment, and audit trails.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityMetadata {

    /* =========================
       Login Tracking (Rolling)
       ========================= */

    /**
     * Number of consecutive failed login attempts
     */
    @Builder.Default
    private int failedLoginAttempts = 0;

    /**
     * Timestamp of most recent failed login
     */
    private Instant lastFailedLoginAt;

    /**
     * Timestamp of most recent successful login
     */
    private Instant lastSuccessfulLoginAt;

    /**
     * Timestamp when failure counter was last reset
     */
    private Instant failedAttemptsResetAt;

    /* =========================
       Password Tracking
       ========================= */

    /**
     * When the password was last changed
     */
    private Instant passwordLastChangedAt;

    /**
     * Whether password is known to be compromised
     * (e.g., found in breach database)
     */
    @Builder.Default
    private boolean passwordCompromised = false;

    /**
     * Source of compromise detection (optional)
     */
    private String compromiseSource;

    /* =========================
       Device Intelligence
       ========================= */

    /**
     * Bounded, ordered set of known device fingerprints
     * (browser fingerprint, device ID, etc.)
     */
    @Builder.Default
    private Set<String> knownDeviceFingerprints = new LinkedHashSet<>();

    /**
     * Device ID from most recent login
     */
    private String lastLoginDeviceId;

    /**
     * User agent from most recent login
     */
    private String lastLoginUserAgent;

    /* =========================
       Location Intelligence
       ========================= */

    /**
     * ISO country code of last login (e.g., "US", "GB")
     */
    private String lastLoginCountry;

    /**
     * City of last login
     */
    private String lastLoginCity;

    /**
     * IP address of last login (IPv4 or IPv6)
     */
    private String lastLoginIp;

    /**
     * Timestamp of last login
     */
    private Instant lastLoginAt;

    /* =========================
       Locking (Temporary)
       ========================= */

    /**
     * Temporary automated lock (e.g. brute force protection)
     * Long-term locks are handled by UserStatus.LOCKED
     */
    private Instant accountLockedUntil;

    /**
     * Reason for temporary lock
     */
    private String lockReason;

    /**
     * Type of lock applied
     */
    private LockType lockType;

    /* =========================
       Risk Scoring
       ========================= */

    /**
     * Computed risk score (0–100)
     * 0 = No risk, 100 = Maximum risk
     */
    @Builder.Default
    private int riskScore = 0;

    /**
     * Last time risk score was recalculated
     */
    private Instant riskScoreUpdatedAt;

    /**
     * Optional explanation for auditors
     */
    private String riskExplanation;

    /**
     * Risk level derived from score
     */
    private RiskLevel riskLevel;

    /* =========================
       Multi-Factor Authentication
       ========================= */

    /**
     * Whether MFA is enabled
     */
    @Builder.Default
    private boolean mfaEnabled = false;

    /**
     * MFA method (e.g., TOTP, SMS, EMAIL)
     */
    private String mfaMethod;

    /**
     * Last time MFA was verified
     */
    private Instant lastMfaVerifiedAt;

    /* =========================
       Domain Helpers - Lock Management
       ========================= */

    /**
     * Check if account is currently under temporary lock.
     *
     * @param clock the clock to use for current time
     * @return true if account is locked
     */
    public boolean isTemporarilyLocked(@NotNull Clock clock) {
        return accountLockedUntil != null &&
                clock.instant().isBefore(accountLockedUntil);
    }

    /**
     * Apply a temporary lock to the account.
     *
     * @param clock the clock to use for current time
     * @param duration how long to lock the account
     * @param reason reason for the lock
     * @param type type of lock
     */
    public void applyTemporaryLock(
            @NotNull Clock clock,
            @NotNull Duration duration,
            @NotNull String reason,
            @NotNull LockType type
    ) {
        this.accountLockedUntil = clock.instant().plus(duration);
        this.lockReason = reason;
        this.lockType = type;
    }

    /**
     * Release the temporary lock.
     */
    public void releaseLock() {
        this.accountLockedUntil = null;
        this.lockReason = null;
        this.lockType = null;
    }

    /**
     * Get remaining lock duration.
     *
     * @param clock the clock to use for current time
     * @return Optional containing remaining duration, empty if not locked
     */
    public Optional<Duration> getRemainingLockDuration(@NotNull Clock clock) {
        if (!isTemporarilyLocked(clock)) {
            return Optional.empty();
        }
        return Optional.of(Duration.between(clock.instant(), accountLockedUntil));
    }

    /* =========================
       Domain Helpers - Login Tracking
       ========================= */

    /**
     * Record a failed login attempt.
     *
     * @param clock the clock to use for current time
     */
    public void recordFailedLogin(@NotNull Clock clock) {
        this.failedLoginAttempts++;
        this.lastFailedLoginAt = clock.instant();
    }

    /**
     * Record a successful login.
     *
     * @param clock the clock to use for current time
     * @param ip IP address of login
     * @param deviceId device identifier
     * @param country country code (optional)
     * @param city city name (optional)
     */
    public void recordSuccessfulLogin(
            @NotNull Clock clock,
            @NotNull String ip,
            String deviceId,
            String country,
            String city
    ) {
        this.lastSuccessfulLoginAt = clock.instant();
        this.lastLoginAt = clock.instant();
        this.lastLoginIp = ip;
        this.lastLoginDeviceId = deviceId;
        this.lastLoginCountry = country;
        this.lastLoginCity = city;
        resetFailures(clock);
    }

    /**
     * Reset failed login counters.
     *
     * @param clock the clock to use for current time
     */
    public void resetFailures(@NotNull Clock clock) {
        this.failedLoginAttempts = 0;
        this.failedAttemptsResetAt = clock.instant();
    }

    /**
     * Check if account has exceeded failed login threshold.
     *
     * @param threshold maximum allowed failed attempts
     * @return true if threshold exceeded
     */
    public boolean hasExceededFailedLoginThreshold(int threshold) {
        return failedLoginAttempts >= threshold;
    }

    /* =========================
       Domain Helpers - Device Management
       ========================= */

    /**
     * Add a known device fingerprint (bounded).
     * Maintains a maximum number of devices, removing oldest when exceeded.
     *
     * @param fingerprint device fingerprint to register
     * @param maxDevices maximum number of devices to track
     */
    public void registerDevice(@NotNull String fingerprint, int maxDevices) {
        knownDeviceFingerprints.add(fingerprint);
        while (knownDeviceFingerprints.size() > maxDevices) {
            knownDeviceFingerprints.iterator().remove();
        }
    }

    /**
     * Check if a device fingerprint is recognized.
     *
     * @param fingerprint device fingerprint to check
     * @return true if device is known
     */
    public boolean isKnownDevice(@NotNull String fingerprint) {
        return knownDeviceFingerprints.contains(fingerprint);
    }

    /**
     * Remove a device fingerprint.
     *
     * @param fingerprint device fingerprint to remove
     * @return true if device was removed
     */
    public boolean removeDevice(@NotNull String fingerprint) {
        return knownDeviceFingerprints.remove(fingerprint);
    }

    /**
     * Clear all known devices.
     */
    public void clearAllDevices() {
        knownDeviceFingerprints.clear();
    }

    /* =========================
       Domain Helpers - Risk Management
       ========================= */

    /**
     * Check if account is considered high risk.
     *
     * @return true if risk score >= 70
     */
    public boolean isHighRisk() {
        return riskScore >= 70;
    }

    /**
     * Check if account is considered medium risk.
     *
     * @return true if risk score is between 40 and 69
     */
    public boolean isMediumRisk() {
        return riskScore >= 40 && riskScore < 70;
    }

    /**
     * Check if account is considered low risk.
     *
     * @return true if risk score < 40
     */
    public boolean isLowRisk() {
        return riskScore < 40;
    }

    /**
     * Update the risk score and level.
     *
     * @param clock the clock to use for current time
     * @param newScore new risk score (0-100)
     * @param explanation optional explanation for the score
     */
    public void updateRiskScore(
            @NotNull Clock clock,
            int newScore,
            String explanation
    ) {
        if (newScore < 0 || newScore > 100) {
            throw new IllegalArgumentException("Risk score must be between 0 and 100");
        }

        this.riskScore = newScore;
        this.riskScoreUpdatedAt = clock.instant();
        this.riskExplanation = explanation;
        this.riskLevel = RiskLevel.fromScore(newScore);
    }

    /**
     * Check if risk score is stale (needs recalculation).
     *
     * @param clock the clock to use for current time
     * @param maxAge maximum age before score is considered stale
     * @return true if score needs recalculation
     */
    public boolean isRiskScoreStale(@NotNull Clock clock, @NotNull Duration maxAge) {
        if (riskScoreUpdatedAt == null) {
            return true;
        }

        Instant staleThreshold = clock.instant().minus(maxAge);
        return riskScoreUpdatedAt.isBefore(staleThreshold);
    }

    /* =========================
       Domain Helpers - Password Management
       ========================= */

    /**
     * Mark password as compromised.
     *
     * @param source source of compromise detection
     */
    public void markPasswordCompromised(@NotNull String source) {
        this.passwordCompromised = true;
        this.compromiseSource = source;
    }

    /**
     * Clear password compromise flag.
     */
    public void clearPasswordCompromise() {
        this.passwordCompromised = false;
        this.compromiseSource = null;
    }

    /**
     * Update password change timestamp.
     *
     * @param clock the clock to use for current time
     */
    public void recordPasswordChange(@NotNull Clock clock) {
        this.passwordLastChangedAt = clock.instant();
        clearPasswordCompromise();
    }

    /**
     * Check if password change is overdue.
     *
     * @param clock the clock to use for current time
     * @param maxAge maximum password age
     * @return true if password should be changed
     */
    public boolean isPasswordChangeOverdue(@NotNull Clock clock, @NotNull Duration maxAge) {
        if (passwordLastChangedAt == null) {
            return true;
        }

        Instant changeThreshold = clock.instant().minus(maxAge);
        return passwordLastChangedAt.isBefore(changeThreshold);
    }

    /* =========================
       Domain Helpers - Location Analysis
       ========================= */

    /**
     * Check if login location has changed since last login.
     *
     * @param newCountry new country code
     * @param newCity new city
     * @return true if location changed
     */
    public boolean isLocationChanged(String newCountry, String newCity) {
        if (lastLoginCountry == null) {
            return true; // First login
        }

        boolean countryChanged = !lastLoginCountry.equals(newCountry);
        boolean cityChanged = lastLoginCity != null &&
                newCity != null &&
                !lastLoginCity.equals(newCity);

        return countryChanged || cityChanged;
    }

    /* =========================
       Supporting Enums
       ========================= */

    /**
     * Type of Account Lock
     */
    public enum LockType {

        BRUTE_FORCE(
                "Brute Force Protection",
                "Account locked due to multiple failed login attempts"
        ),

        SUSPICIOUS_ACTIVITY(
                "Suspicious Activity",
                "Account locked due to suspicious behavior"
        ),

        LOCATION_ANOMALY(
                "Location Anomaly",
                "Account locked due to unusual login location"
        ),

        DEVICE_ANOMALY(
                "Device Anomaly",
                "Account locked due to unrecognized device"
        ),

        MANUAL(
                "Manual Lock",
                "Account manually locked by administrator"
        );

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

    /**
     * Risk Level Classification
     */
    public enum RiskLevel {

        LOW(
                "Low Risk",
                0,
                39
        ),

        MEDIUM(
                "Medium Risk",
                40,
                69
        ),

        HIGH(
                "High Risk",
                70,
                89
        ),

        CRITICAL(
                "Critical Risk",
                90,
                100
        );

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

        public int getMinScore() {
            return minScore;
        }

        public int getMaxScore() {
            return maxScore;
        }

        /**
         * Determine risk level from score.
         *
         * @param score risk score (0-100)
         * @return corresponding risk level
         */
        public static RiskLevel fromScore(int score) {
            if (score < 0 || score > 100) {
                throw new IllegalArgumentException("Risk score must be between 0 and 100");
            }

            for (RiskLevel level : values()) {
                if (score >= level.minScore && score <= level.maxScore) {
                    return level;
                }
            }

            return LOW; // Fallback
        }

        @Override
        public String toString() {
            return name() + " (" + displayName + ")";
        }
    }
}
