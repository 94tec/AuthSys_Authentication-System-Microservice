package com.techStack.authSys.identity.service;

import com.techStack.authSys.auth.service.FirebaseServiceAuth;
import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.identity.dto.UserProfileDTO;
import com.techStack.authSys.identity.models.UserProfile;
import com.techStack.authSys.identity.repository.UserProfileRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.modelmapper.PropertyMap;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserProfileService {

    private static final String OWNS_RESOURCE =
            "(authentication.principal instanceof T(com.techStack.authSys.auth.context.CustomUserDetails) " +
                    "and #userId == authentication.principal.userId) or " +
                    "(authentication.principal instanceof T(String) and #userId == authentication.principal)";

    private final UserProfileRepository userProfileRepository;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final ModelMapper modelMapper;
    private final Clock clock;

    /**
     * UserProfile.userId is ambiguous to ModelMapper's implicit matcher: it also
     * finds UserProfile.getId(), and (via the embedded User reference) User.getId()
     * and User.getUserProfileId() as candidate sources for UserProfileDTO.setUserId().
     * Configuring an explicit mapping for just this property removes the ambiguity
     * without touching the shared ModelMapper bean's global config or other mappings.
     */
    @PostConstruct
    private void configureMappings() {
        modelMapper.addMappings(new PropertyMap<UserProfile, UserProfileDTO>() {
            @Override
            protected void configure() {
                map().setUserId(source.getUserId());
            }
        });
    }
    @PreAuthorize("hasAuthority('profile:create') or " + OWNS_RESOURCE)
    public Mono<UserProfileDTO> createUserProfile(String userId, UserProfileDTO profileDTO) {
        Instant now = clock.instant();

        log.info("Creating user profile for {} at {}", userId, now);

        return firebaseServiceAuth.getUserById(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "User not found with ID: " + userId)))
                .flatMap(user -> {
                    UserProfile userProfile = modelMapper.map(profileDTO, UserProfile.class);
                    userProfile.setUserId(userId);
                    userProfile.setCreatedAt(now);
                    userProfile.setUpdatedAt(now);

                    return userProfileRepository.save(userProfile);
                })
                .map(savedProfile -> {
                    log.info("Created user profile for {} at {}", userId, now);
                    return modelMapper.map(savedProfile, UserProfileDTO.class);
                })
                .doOnError(e -> log.error("Error creating profile for {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    public Mono<UserProfileDTO> createDefaultProfile(String userId) {
        Instant now = clock.instant();

        log.info("No existing profile for {} — provisioning a default one at {}", userId, now);

        return firebaseServiceAuth.getUserById(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "User not found with ID: " + userId)))
                .flatMap(user -> {
                    UserProfile profile = UserProfile.builder()
                            .userId(userId)
                            .firstName(user.getFirstName())
                            .lastName(user.getLastName())
                            .isPublic(false)
                            .createdAt(now)
                            .updatedAt(now)
                            .build();
                    return userProfileRepository.save(profile);
                })
                .map(saved -> {
                    log.info("Default profile provisioned for {} at {}", userId, now);
                    return modelMapper.map(saved, UserProfileDTO.class);
                })
                .doOnError(e -> log.error("Error provisioning default profile for {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    @PreAuthorize("hasAuthority('profile:read') or " + OWNS_RESOURCE)
    public Mono<UserProfileDTO> getUserProfile(String userId) {
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

    @PreAuthorize("hasAuthority('profile:update') or " + OWNS_RESOURCE)
    public Mono<UserProfileDTO> updateUserProfile(String userId, UserProfileDTO profileDTO) {
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
                    profile.setPhoneNumber(profileDTO.getPhoneNumber());
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

    @PreAuthorize("hasAuthority('profile:delete') or " + OWNS_RESOURCE)
    public Mono<Void> deleteUserProfile(String userId) {
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

    public Mono<Boolean> profileExists(String userId) {
        Instant now = clock.instant();

        return userProfileRepository.findByUserId(userId)
                .map(profile -> true)
                .defaultIfEmpty(false)
                .doOnSuccess(exists -> log.debug("Profile exists check for {} at {}: {}",
                        userId, now, exists));
    }

    public Mono<Instant> getProfileCreationTime(String userId) {
        return userProfileRepository.findByUserId(userId)
                .map(UserProfile::getCreatedAt)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)));
    }

    public Mono<Instant> getProfileLastUpdateTime(String userId) {
        return userProfileRepository.findByUserId(userId)
                .map(UserProfile::getUpdatedAt)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "UserProfile not found for User ID: " + userId)));
    }
}