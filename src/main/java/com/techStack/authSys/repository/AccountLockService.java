package com.techStack.authSys.repository;


import reactor.core.publisher.Mono;

import java.time.Duration;

public interface AccountLockService {

    /**
     * Checks if an account is currently locked
     */
    boolean isAccountLocked(String userId);

    /**
     * Locks an account with a specified reason and duration
     *
     * @return
     */
    Mono<Void> lockAccount(String userId, String reason, Duration lockDuration);

    /**
     * Unlocks an account manually
     */
    void unlockAccount(String userId);

    /**
     * Gets the remaining lock time for an account
     */
    Duration getRemainingLockTime(String userId);

    /**
     * Records a failed login attempt
     */
    void recordFailedAttempt(String userId, String ipAddress);
}
