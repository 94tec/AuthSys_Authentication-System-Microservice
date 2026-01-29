package com.techStack.authSys.models.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

/**
 * User Password History Entry
 *
 * Immutable audit record for password changes.
 * Used for password reuse prevention, expiry enforcement,
 * and security auditing.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPasswordHistory {

    /**
     * Hashed password (BCrypt / Argon2 / etc)
     */
    private String passwordHash;

    /**
     * Hashing algorithm used (e.g. BCRYPT, ARGON2)
     */
    private PasswordHashAlgorithm hashAlgorithm;

    /**
     * When this password was set
     */
    private Instant changedAt;

    /**
     * IP address where password was changed
     * Stored as string to support IPv4/IPv6
     */
    private String changedFromIp;

    /**
     * Sequential version of the password
     * Higher = newer
     */
    private long version;

    /**
     * Why the password was changed
     */
    private PasswordChangeReason reason;

    /**
     * Whether this password is the current active one
     * (useful for migrations & cleanup)
     */
    private boolean current;

    /* =========================
       Business Logic Methods
       ========================= */

    /**
     * Check if this password entry matches a given plain text password.
     *
     * @param plainPassword the plain text password to check
     * @return true if password matches
     */
    public boolean matches(@NotNull String plainPassword) {
        if (passwordHash == null || hashAlgorithm == null) {
            return false;
        }
        return hashAlgorithm.verify(plainPassword, passwordHash);
    }

    /**
     * Check if this password has expired based on a given policy.
     *
     * @param expiryDays number of days until password expires
     * @return true if password has expired
     */
    public boolean isExpired(int expiryDays) {
        if (changedAt == null || expiryDays <= 0) {
            return false;
        }

        Instant expiryDate = changedAt.plusSeconds(expiryDays * 86400L);
        return Instant.now().isAfter(expiryDate);
    }

    /**
     * Check if this password change occurred within a given time window.
     *
     * @param referenceTime the time to compare against
     * @return true if password was changed after referenceTime
     */
    public boolean isChangedAfter(@NotNull Instant referenceTime) {
        return changedAt != null && changedAt.isAfter(referenceTime);
    }

    /**
     * Check if this password change was security-related.
     *
     * @return true if change was due to compromise or expiry
     */
    public boolean isSecurityRelated() {
        return reason == PasswordChangeReason.COMPROMISED ||
                reason == PasswordChangeReason.EXPIRED;
    }

    /* =========================
       Supporting Enums
       ========================= */

    /**
     * Password Change Reason
     *
     * Tracks why a password was changed for audit and security purposes.
     */
    public enum PasswordChangeReason {

        USER_INITIATED(
                "User Initiated",
                "User voluntarily changed their password",
                false
        ),

        ADMIN_RESET(
                "Admin Reset",
                "Password reset by administrator",
                true
        ),

        EXPIRED(
                "Expired",
                "Password changed due to expiration policy",
                true
        ),

        COMPROMISED(
                "Compromised",
                "Password changed due to security compromise",
                true
        ),

        FIRST_LOGIN(
                "First Login",
                "Initial password set on first login",
                false
        );

        private final String displayName;
        private final String description;
        private final boolean forced;

        PasswordChangeReason(String displayName, String description, boolean forced) {
            this.displayName = displayName;
            this.description = description;
            this.forced = forced;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getDescription() {
            return description;
        }

        /**
         * Check if this change was forced (not user-initiated).
         *
         * @return true if password change was mandatory
         */
        public boolean isForced() {
            return forced;
        }

        /**
         * Check if this reason indicates a security event.
         *
         * @return true if reason is security-related
         */
        public boolean isSecurityEvent() {
            return this == COMPROMISED || this == EXPIRED;
        }

        /**
         * Attempts to resolve a reason from a case-insensitive name.
         *
         * @param name the reason name (case-insensitive)
         * @return Optional containing the reason if found, empty otherwise
         */
        public static Optional<PasswordChangeReason> fromName(String name) {
            if (name == null || name.isBlank()) {
                return Optional.empty();
            }

            try {
                return Optional.of(PasswordChangeReason.valueOf(name.toUpperCase().trim()));
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
        }

        @Override
        public String toString() {
            return name() + " (" + displayName + ")";
        }
    }

    /**
     * Password Hash Algorithm
     *
     * Supported password hashing algorithms with verification logic.
     */
    public enum PasswordHashAlgorithm {

        BCRYPT(
                "BCrypt",
                "BCrypt hashing algorithm (recommended)",
                10  // default cost factor
        ),

        ARGON2(
                "Argon2",
                "Argon2id hashing algorithm (most secure)",
                16  // default memory cost in MB
        );

        private final String displayName;
        private final String description;
        private final int defaultStrength;

        PasswordHashAlgorithm(String displayName, String description, int defaultStrength) {
            this.displayName = displayName;
            this.description = description;
            this.defaultStrength = defaultStrength;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getDescription() {
            return description;
        }

        public int getDefaultStrength() {
            return defaultStrength;
        }

        /**
         * Verify if a plain text password matches a hash.
         *
         * @param plainPassword the plain text password
         * @param passwordHash the hashed password
         * @return true if password matches
         */
        public boolean verify(@NotNull String plainPassword, @NotNull String passwordHash) {
            return switch (this) {
                case BCRYPT -> verifyBCrypt(plainPassword, passwordHash);
                case ARGON2 -> verifyArgon2(plainPassword, passwordHash);
            };
        }

        /**
         * Hash a plain text password using this algorithm.
         *
         * @param plainPassword the plain text password
         * @return hashed password
         */
        public String hash(@NotNull String plainPassword) {
            return switch (this) {
                case BCRYPT -> hashBCrypt(plainPassword, defaultStrength);
                case ARGON2 -> hashArgon2(plainPassword, defaultStrength);
            };
        }

        /**
         * Check if a hash needs to be upgraded (rehashed with current settings).
         *
         * @param passwordHash the existing hash
         * @return true if hash should be upgraded
         */
        public boolean needsUpgrade(@NotNull String passwordHash) {
            return switch (this) {
                case BCRYPT -> needsBCryptUpgrade(passwordHash, defaultStrength);
                case ARGON2 -> needsArgon2Upgrade(passwordHash, defaultStrength);
            };
        }

        /* =========================
           Algorithm-Specific Methods
           (Implement with actual crypto libraries)
           ========================= */

        private boolean verifyBCrypt(String plainPassword, String hash) {
            // TODO: Implement with BCryptPasswordEncoder or similar
            // return BCrypt.checkpw(plainPassword, hash);
            throw new UnsupportedOperationException("BCrypt verification not implemented");
        }

        private boolean verifyArgon2(String plainPassword, String hash) {
            // TODO: Implement with Argon2PasswordEncoder or similar
            // return argon2.verify(hash, plainPassword.toCharArray());
            throw new UnsupportedOperationException("Argon2 verification not implemented");
        }

        private String hashBCrypt(String plainPassword, int strength) {
            // TODO: Implement with BCryptPasswordEncoder
            // return BCrypt.hashpw(plainPassword, BCrypt.gensalt(strength));
            throw new UnsupportedOperationException("BCrypt hashing not implemented");
        }

        private String hashArgon2(String plainPassword, int strength) {
            // TODO: Implement with Argon2PasswordEncoder
            // return argon2.hash(plainPassword.toCharArray());
            throw new UnsupportedOperationException("Argon2 hashing not implemented");
        }

        private boolean needsBCryptUpgrade(String hash, int targetStrength) {
            // TODO: Check if BCrypt rounds < targetStrength
            return false;
        }

        private boolean needsArgon2Upgrade(String hash, int targetStrength) {
            // TODO: Check if Argon2 params < targetStrength
            return false;
        }

        /**
         * Attempts to resolve an algorithm from a case-insensitive name.
         *
         * @param name the algorithm name (case-insensitive)
         * @return Optional containing the algorithm if found, empty otherwise
         */
        public static Optional<PasswordHashAlgorithm> fromName(String name) {
            if (name == null || name.isBlank()) {
                return Optional.empty();
            }

            try {
                return Optional.of(PasswordHashAlgorithm.valueOf(name.toUpperCase().trim()));
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
        }

        /**
         * Get the recommended algorithm for new password hashes.
         *
         * @return recommended algorithm
         */
        public static PasswordHashAlgorithm getRecommended() {
            return ARGON2;  // Most secure
        }

        @Override
        public String toString() {
            return name() + " (" + displayName + ")";
        }
    }
}