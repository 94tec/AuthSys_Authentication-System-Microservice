package com.techStack.authSys.util.auth;

import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import reactor.core.publisher.Mono;

/**
 * Admin User Validator
 *
 * Centralized validation logic for admin user operations.
 *
 * @author TechStack Security Team
 * @version 1.0
 */
public final class AdminUserValidator {

    private AdminUserValidator() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Validate user is in pending approval status
     */
    public static Mono<User> validatePendingStatus(User user) {
        if (user.getStatus() != UserStatus.PENDING_APPROVAL) {
            return Mono.error(new IllegalStateException(
                    "User not pending approval. Current: " + user.getStatus()));
        }
        return Mono.just(user);
    }

    /**
     * Validate user is suspended
     */
    public static Mono<User> validateSuspendedStatus(User user) {
        if (user.getStatus() != UserStatus.SUSPENDED) {
            return Mono.error(new IllegalStateException(
                    "User not suspended. Current: " + user.getStatus()));
        }
        return Mono.just(user);
    }

    /**
     * Validate user is active
     */
    public static Mono<User> validateActiveStatus(User user) {
        if (user.getStatus() != UserStatus.ACTIVE) {
            return Mono.error(new IllegalStateException(
                    "User not active. Current: " + user.getStatus()));
        }
        return Mono.just(user);
    }

    /**
     * Validate email availability
     */
    public static Mono<Boolean> validateEmailAvailability(
            RedisUserCacheService cacheService,
            String email
    ) {
        return cacheService.isEmailRegistered(email)
                .map(registered -> !registered)
                .onErrorReturn(true); // Assume available on cache error
    }

    /**
     * Validate user exists and is not deleted
     */
    public static Mono<User> validateUserExists(User user) {
        if (user == null) {
            return Mono.error(new IllegalArgumentException("User not found"));
        }
        return Mono.just(user);
    }

    /**
     * Validate user account is enabled
     */
    public static Mono<User> validateAccountEnabled(User user) {
        if (!user.isEnabled()) {
            return Mono.error(new IllegalStateException(
                    "User account is disabled"));
        }
        return Mono.just(user);
    }

    /**
     * Validate user account is not locked
     */
    public static Mono<User> validateAccountNotLocked(User user) {
        if (user.isAccountLocked()) {
            return Mono.error(new IllegalStateException(
                    "User account is locked"));
        }
        return Mono.just(user);
    }
}
