package com.techStack.authSys.repository.sucurity;

import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Account Lock Service
 *
 * Manages account locking and unlocking based on failed login attempts.
 * Supports both reactive and blocking operations.
 */
public interface AccountLockService {

    /* =========================
       Lock Status Checks
       ========================= */

    /**
     * Check if an account is currently locked
     *
     * @param userId User identifier
     * @return true if account is locked, false otherwise
     */
    boolean isAccountLocked(String userId);

    /**
     * Check if an account is currently locked (reactive)
     *
     * @param userId User identifier
     * @return Mono emitting true if locked, false otherwise
     */
    Mono<Boolean> isAccountLockedReactive(String userId);

    /* =========================
       Lock Management
       ========================= */

    /**
     * Lock an account with a specified reason and duration
     *
     * @param userId User identifier
     * @param reason Reason for locking
     * @param lockDuration Duration of the lock
     * @return Mono that completes when lock is applied
     */
    Mono<Void> lockAccount(String userId, String reason, Duration lockDuration);

    /**
     * Lock an account until a specific time
     *
     * @param userId User identifier
     * @param reason Reason for locking
     * @param unlockTime Instant when the account will be unlocked
     * @return Mono that completes when lock is applied
     */
    Mono<Void> lockAccountUntil(String userId, String reason, Instant unlockTime);

    /**
     * Unlock an account manually
     *
     * @param userId User identifier
     */
    void unlockAccount(String userId);

    /**
     * Unlock an account manually (reactive)
     *
     * @param userId User identifier
     * @return Mono that completes when account is unlocked
     */
    Mono<Void> unlockAccountReactive(String userId);

    /* =========================
       Lock Duration & Timing
       ========================= */

    /**
     * Get the remaining lock time for an account
     *
     * @param userId User identifier
     * @return Duration until unlock, or Duration.ZERO if not locked
     */
    Duration getRemainingLockTime(String userId);

    /**
     * Get the lock duration for an account
     *
     * @param userId User identifier
     * @return Optional containing the lock duration if locked
     */
    Optional<Duration> getLockDuration(String userId);

    /**
     * Get the unlock time for an account
     *
     * @param userId User identifier
     * @return Optional containing the unlock timestamp if locked
     */
    Optional<Instant> getUnlockTime(String userId);

    /**
     * Get the time when the account was locked
     *
     * @param userId User identifier
     * @return Optional containing the lock timestamp if locked
     */
    Optional<Instant> getLockTime(String userId);

    /* =========================
       Failed Attempts
       ========================= */

    /**
     * Record a failed login attempt
     *
     * @param userId User identifier
     * @param ipAddress IP address of the failed attempt
     */
    void recordFailedAttempt(String userId, String ipAddress);

    /**
     * Record a failed login attempt (reactive)
     *
     * @param userId User identifier
     * @param ipAddress IP address of the failed attempt
     * @return Mono that completes when attempt is recorded
     */
    Mono<Void> recordFailedAttemptReactive(String userId, String ipAddress);

    /**
     * Get the number of failed login attempts
     *
     * @param userId User identifier
     * @return Number of failed attempts
     */
    int getFailedAttemptCount(String userId);

    /**
     * Reset failed login attempts counter
     *
     * @param userId User identifier
     */
    void resetFailedAttempts(String userId);

    /**
     * Reset failed login attempts counter (reactive)
     *
     * @param userId User identifier
     * @return Mono that completes when counter is reset
     */
    Mono<Void> resetFailedAttemptsReactive(String userId);

    /* =========================
       Lock Reason & Metadata
       ========================= */

    /**
     * Get the reason for the account lock
     *
     * @param userId User identifier
     * @return Optional containing the lock reason if locked
     */
    Optional<String> getLockReason(String userId);

    /**
     * Get the IP address of the last failed attempt
     *
     * @param userId User identifier
     * @return Optional containing the IP address if available
     */
    Optional<String> getLastFailedAttemptIp(String userId);

    /**
     * Get the timestamp of the last failed attempt
     *
     * @param userId User identifier
     * @return Optional containing the timestamp if available
     */
    Optional<Instant> getLastFailedAttemptTime(String userId);

    /* =========================
       Cleanup Operations
       ========================= */

    /**
     * Check and auto-unlock expired locks
     * Should be called periodically (e.g., via scheduled task)
     *
     * @return Mono that completes when cleanup is done
     */
    Mono<Void> cleanupExpiredLocks();

    /**
     * Remove all lock data for a user
     *
     * @param userId User identifier
     * @return Mono that completes when data is removed
     */
    Mono<Void> removeLockData(String userId);
}
