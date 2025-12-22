package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Handles user creation and coordinates persistence and metadata logging.
 *
 * FIX: This service now correctly delegates the atomic user creation (including
 * roles, permissions, profile, and history) to FirebaseServiceAuth.
 * It focuses only on peripheral tasks like metadata logging and post-creation caching.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserCreationService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RegistrationMetadataService metadataService;
    private final RedisUserCacheService redisCacheService;

    // roleAssignmentService and deviceVerificationService are no longer needed here
    // as their functionality is directly called within firebaseServiceAuth.

    /**
     * Creates a user with roles and persists all related data atomically.
     *
     * The core logic (Firebase Auth, Firestore documents, roles, and initial
     * permissions/pending status) is handled within createFirebaseUser.
     * This method chains non-critical metadata logging and caching.
     *
     * @param userDto The data transfer object for the new user.
     * @param ipAddress The IP address of the requester.
     * @param deviceFingerprint The device fingerprint of the requester.
     * @return Mono<User> The created and persisted User object.
     */
    public Mono<User> createUserWithRoles(
            UserDTO userDto,
            String ipAddress,
            String deviceFingerprint) {

        log.info("Starting atomic user creation for: {}", userDto.getEmail());

        return firebaseServiceAuth.createFirebaseUser(userDto, ipAddress, deviceFingerprint)
                .flatMap(user -> persistMetadataAndCache(user, ipAddress))
                .doOnSuccess(user -> log.info("✅ Full registration chain complete for user: {}", user.getEmail()));
    }

    /**
     * Handles non-atomic, peripheral persistence tasks after the core user object is created.
     */
    private Mono<User> persistMetadataAndCache(User user, String ipAddress) {
        // Log registration metadata
        return metadataService.saveRegistrationMetadata(user, ipAddress)
                // Cache the registered email
                .then(cacheUserEmail(user))
                .thenReturn(user);
    }

    /**
     * Caches the registered email (best-effort, non-blocking).
     * Caching should be fire-and-forget or handled gracefully not to break the main flow.
     */
    private Mono<Void> cacheUserEmail(User user) {
        // Use Mono.defer + subscribeOn(Schedulers.boundedElastic()) for non-blocking execution
        return Mono.defer(() -> {
            log.debug("Attempting to cache registered email: {}", user.getEmail());
            // Using subscribe() outside of a chain is typical for fire-and-forget/best-effort operations
            redisCacheService.cacheRegisteredEmail(user.getEmail())
                    .doOnError(e -> log.warn("Failed to cache email for {}: {}",
                            user.getEmail(), e.getMessage()))
                    .subscribeOn(Schedulers.boundedElastic())
                    .subscribe();
            return Mono.empty();
        });
    }

    // ============================================================================
    // REMOVED METHODS: Logic is consolidated in FirebaseServiceAuth
    // ============================================================================

    /*
     * The following methods were removed because:
     * 1. assignRolesAndPermissions (and related helpers) - The permission resolution
     * and status setting (ACTIVE/PENDING) is now done atomically inside
     * FirebaseServiceAuth.saveUserWithRolesAndPermissions.
     * 2. persistUserData - The critical persistence steps (Firestore documents,
     * device fingerprint) are now part of the atomic call to
     * firebaseServiceAuth.createFirebaseUser().
     */
}