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

import java.time.Clock;
import java.util.Set;

/**
 * User Creation Service
 *
 * Responsibilities:
 * - Registration orchestration
 * - Enforces creation order invariants
 * - Delegates domain logic and persistence
 *
 * Invariants:
 * - Firebase user is created exactly once
 * - Role evaluation occurs before persistence
 * - UID-dependent work happens after Firebase creation
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
        log.info("Starting registration for {}", userDto.getEmail());

        User user = UserFactory.createNewUser(
                userDto.getEmail(),
                userDto.getFirstName(),
                userDto.getLastName(),
                clock
        );

        enrichUserFromDto(user, userDto);

        /*
         * PIPELINE INVARIANTS:
         * 1. Evaluate registration (NO persistence)
         * 2. Create Firebase user (exactly once)
         * 3. Assign roles & permissions (UID exists)
         * 4. Persist metadata & cache ( the best effort)
         */
        return roleAssignmentService.evaluateRegistration(
                        user,
                        user.getRequestedRoles(),
                        ipAddress
                )
                .flatMap(evaluatedUser ->
                        firebaseServiceAuth.createFirebaseUser(
                                evaluatedUser,
                                userDto.getPassword(),
                                ipAddress,
                                deviceFingerprint
                        )
                )
                .flatMap(createdUser ->
                        roleAssignmentService.assignRolesAndPermissions(
                                createdUser,
                                clock.instant()
                        )
                )
                .flatMap(createdUser ->
                        persistMetadataAndCache(
                                createdUser,
                                ipAddress,
                                deviceFingerprint
                        )
                )
                .doOnSuccess(u ->
                        log.info("✅ Registration complete for {}", u.getEmail())
                );
    }

    /**
     * Enrich user entity with DTO data
     *
     * NOTE:
     * Requested roles are stored ONLY on the domain object.
     * This is the single source of truth.
     */
    private void enrichUserFromDto(User user, UserRegistrationDTO userDto) {
        user.setIdentityNo(userDto.getIdentityNo());
        user.setPhoneNumber(userDto.getPhoneNumber());
        user.setDepartment(userDto.getDepartment());

        Set<Roles> requestedRoles = parseRequestedRoles(userDto);
        user.setRequestedRoles(requestedRoles);
    }

    /**
     * Parse requested roles from DTO
     */
    private Set<Roles> parseRequestedRoles(UserRegistrationDTO userDto) {
        if (userDto.getRequestedRole() == null || userDto.getRequestedRole().isBlank()) {
            return Set.of(Roles.USER);
        }

        return Roles.fromName(userDto.getRequestedRole())
                .map(Set::of)
                .orElse(Set.of(Roles.USER));
    }

    /**
     * Peripheral persistence (non-blocking, best-effort)
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
     * Best-effort email caching (reactive-safe)
     */
    private Mono<Void> cacheUserEmail(User user) {
        return redisCacheService.cacheRegisteredEmail(user.getEmail())
                .doOnError(e -> log.warn(
                        "Failed to cache registered email for {}: {}",
                        user.getEmail(),
                        e.getMessage()
                ))
                .onErrorResume(e -> Mono.empty());
    }
}
