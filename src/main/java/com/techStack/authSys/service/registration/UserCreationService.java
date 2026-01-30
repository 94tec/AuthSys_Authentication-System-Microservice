package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserFactory;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * User Creation Service
 *
 * Handles user creation and coordinates persistence.
 * Delegates atomic user creation to FirebaseServiceAuth.
 * Focuses on peripheral tasks like metadata logging and caching.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserCreationService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RoleAssignmentService roleAssignmentService;
    private final RegistrationMetadataService metadataService;
    private final RedisUserCacheService redisCacheService;
    private final Clock clock;

    /**
     * Create user with roles and persist all related data atomically
     */
    public Mono<User> createUserWithRoles(
            UserRegistrationDTO userDto,
            String ipAddress,
            String deviceFingerprint
    ) {
        log.info("Starting atomic user creation for: {}", userDto.getEmail());

        // Parse requested roles
        Set<Roles> requestedRoles = parseRequestedRoles(userDto);

        // Create base user from factory
        User user = UserFactory.createNewUser(
                userDto.getEmail(),
                userDto.getFirstName(),
                userDto.getLastName(),
                clock
        );

        // Set additional user properties
        enrichUserFromDto(user, userDto);

        // Process registration through role assignment service
        return roleAssignmentService.processUserRegistration(
                        user,
                        requestedRoles,
                        ipAddress,
                        deviceFingerprint
                )
                .flatMap(createdUser ->
                        firebaseServiceAuth.createFirebaseUser(userDto, ipAddress, deviceFingerprint)
                )
                .flatMap(createdUser -> persistMetadataAndCache(createdUser, ipAddress, deviceFingerprint))
                .doOnSuccess(createdUser ->
                        log.info("✅ Full registration chain complete for user: {}", createdUser.getEmail())
                );
    }

    /**
     * Parse requested roles from DTO
     */
    private Set<Roles> parseRequestedRoles(UserRegistrationDTO userDto) {
        if (userDto.getRequestedRole() == null || userDto.getRequestedRole().isBlank()) {
            return Set.of(Roles.USER); // Default role
        }

        return Roles.fromName(userDto.getRequestedRole())
                .map(Set::of)
                .orElse(Set.of(Roles.USER));
    }

    /**
     * Enrich user entity with DTO data
     */
    private void enrichUserFromDto(User user, UserRegistrationDTO userDto) {
        user.setIdentityNo(userDto.getIdentityNo());
        user.setPhoneNumber(userDto.getPhoneNumber());
        user.setDepartment(userDto.getDepartment());

        // Set requested role
        if (userDto.getRequestedRole() != null) {
            Roles.fromName(userDto.getRequestedRole())
                    .ifPresent(user::setRequestedRole);
        }
    }

    /**
     * Handle peripheral persistence tasks after core user creation
     */
    private Mono<User> persistMetadataAndCache(
            User user,
            String ipAddress,
            String deviceFingerprint
    ) {
        return metadataService.saveRegistrationMetadata(user, ipAddress, deviceFingerprint)
                .then(cacheUserEmail(user))
                .thenReturn(user);
    }

    /**
     * Cache registered email (best-effort, non-blocking)
     */
    private Mono<Void> cacheUserEmail(User user) {
        return Mono.defer(() -> {
            log.debug("Attempting to cache registered email: {}", user.getEmail());

            redisCacheService.cacheRegisteredEmail(user.getEmail())
                    .doOnError(e -> log.warn("Failed to cache email for {}: {}",
                            user.getEmail(), e.getMessage()))
                    .subscribeOn(Schedulers.boundedElastic())
                    .subscribe();

            return Mono.empty();
        });
    }
}