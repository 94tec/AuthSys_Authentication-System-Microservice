package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.response.UserProfileDTO;
import com.techStack.authSys.exception.resource.ResourceNotFoundException;
import com.techStack.authSys.models.user.UserProfile;
import com.techStack.authSys.repository.user.UserProfileRepository;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * User Profile Service
 *
 * Manages user profile operations.
 * Uses Clock for all timestamp operations.
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserProfileService {

    private final UserProfileRepository userProfileRepository;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final ModelMapper modelMapper;
    private final Clock clock;

    /* =========================
       Profile Creation
       ========================= */

    /**
     * Create user profile
     */
    @PreAuthorize("hasAuthority('profile:create') or #userId.toString() == authentication.name")
    public Mono<UserProfileDTO> createUserProfile(UUID userId, UserProfileDTO profileDTO) {
        Instant now = clock.instant();
        String userIdStr = userId.toString();

        log.info("Creating user profile for {} at {}", userIdStr, now);

        return firebaseServiceAuth.getUserById(userIdStr)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "User not found with ID: " + userId)))
                .flatMap(user -> {
                    UserProfile userProfile = modelMapper.map(profileDTO, UserProfile.class);
                    userProfile.setUserId(userIdStr);
                    userProfile.setCreatedAt(now);
                    userProfile.setUpdatedAt(now);

                    return userProfileRepository.save(userProfile);
                })
                .map(savedProfile -> {
                    log.info("Created user profile for {} at {}", userIdStr, now);
                    return modelMapper.map(savedProfile, UserProfileDTO.class);
                })
                .doOnError(e -> log.error("Error creating profile for {} at {}: {}",
                        userIdStr, now, e.getMessage()));
    }

    /* =========================
       Profile Retrieval
       ========================= */

    /**
     * Get user profile by ID
     */
    @PreAuthorize("hasAuthority('profile:read') or #userId == authentication.principal.id")
    public Mono<UserProfileDTO> getUserProfile(UUID userId) {
        Instant now = clock.instant();

        log.debug("Retrieving user profile for {} at {}", userId, now);

        return userProfileRepository.findByUserId(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)))
                .map(profile -> {
                    log.debug("Retrieved user profile for {} at {}", userId, now);
                    return modelMapper.map(profile, UserProfileDTO.class);
                })
                .doOnError(e -> log.error("Error retrieving profile for {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /* =========================
       Profile Updates
       ========================= */

    /**
     * Update user profile
     */
    @PreAuthorize("hasAuthority('profile:update') or #userId == authentication.principal.id")
    public Mono<UserProfileDTO> updateUserProfile(UUID userId, UserProfileDTO profileDTO) {
        Instant now = clock.instant();

        log.info("Updating user profile for {} at {}", userId, now);

        return userProfileRepository.findByUserId(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)))
                .flatMap(profile -> {
                    profile.setFirstName(profileDTO.getFirstName());
                    profile.setLastName(profileDTO.getLastName());
                    profile.setProfilePictureUrl(profileDTO.getProfilePictureUrl());
                    profile.setBio(profileDTO.getBio());
                    profile.setPublic(profileDTO.isPublic());
                    profile.setUpdatedAt(now);

                    return userProfileRepository.save(profile);
                })
                .map(updatedProfile -> {
                    log.info("Updated user profile for {} at {}", userId, now);
                    return modelMapper.map(updatedProfile, UserProfileDTO.class);
                })
                .doOnError(e -> log.error("Error updating profile for {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /* =========================
       Profile Deletion
       ========================= */

    /**
     * Delete user profile
     */
    @PreAuthorize("hasAuthority('profile:delete') or #userId == authentication.principal.id")
    public Mono<Void> deleteUserProfile(UUID userId) {
        Instant now = clock.instant();

        log.info("Deleting user profile for {} at {}", userId, now);

        return userProfileRepository.findByUserId(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)))
                .flatMap(profile -> userProfileRepository.delete(profile))
                .doOnSuccess(v -> log.info("Deleted user profile for {} at {}", userId, now))
                .doOnError(e -> log.error("Error deleting profile for {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /* =========================
       Profile Validation
       ========================= */

    /**
     * Check if profile exists
     */
    public Mono<Boolean> profileExists(UUID userId) {
        Instant now = clock.instant();

        return userProfileRepository.findByUserId(userId)
                .map(profile -> true)
                .defaultIfEmpty(false)
                .doOnSuccess(exists -> log.debug("Profile exists check for {} at {}: {}",
                        userId, now, exists));
    }

    /**
     * Get profile creation time
     */
    public Mono<Instant> getProfileCreationTime(UUID userId) {
        return userProfileRepository.findByUserId(userId)
                .map(UserProfile::getCreatedAt)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)));
    }

    /**
     * Get profile last update time
     */
    public Mono<Instant> getProfileLastUpdateTime(UUID userId) {
        return userProfileRepository.findByUserId(userId)
                .map(UserProfile::getUpdatedAt)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)));
    }
}