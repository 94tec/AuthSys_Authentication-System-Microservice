package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Handles user creation, role assignment, and persistence.
 * Coordinates Firebase Auth creation with Firestore document creation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserCreationService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RoleAssignmentService roleAssignmentService;
    private final DeviceVerificationService deviceVerificationService;
    private final RegistrationMetadataService metadataService;
    private final RedisCacheService redisCacheService;

    /**
     * Creates a user with roles and persists all related data.
     */
    public Mono<User> createUserWithRoles(
            UserDTO userDto,
            String ipAddress,
            String deviceFingerprint) {

        return firebaseServiceAuth.createFirebaseUser(userDto, ipAddress, deviceFingerprint)
                .flatMap(user -> assignRolesAndPermissions(user, userDto))
                .flatMap(user -> persistUserData(user, ipAddress, deviceFingerprint));
    }

    /**
     * Assigns roles and permissions based on user type.
     */
    private Mono<User> assignRolesAndPermissions(User user, UserDTO userDto) {
        boolean isPrivileged = isPrivilegedUser(userDto);

        if (isPrivileged) {
            return assignPrivilegedRoles(user, userDto);
        } else {
            return assignRegularUserPermissions(user);
        }
    }

    /**
     * Checks if user has privileged roles.
     */
    private boolean isPrivilegedUser(UserDTO userDto) {
        return userDto.getRoles().stream()
                .anyMatch(role -> role.equalsIgnoreCase("ADMIN") ||
                        role.equalsIgnoreCase("SUPER_ADMIN") ||
                        role.equalsIgnoreCase("MANAGER"));
    }

    /**
     * Assigns privileged roles and their associated permissions.
     */
    private Mono<User> assignPrivilegedRoles(User user, UserDTO userDto) {
        log.info("🔐 Assigning privileged roles for user: {}", user.getEmail());

        List<Roles> roleEnums = convertToRoleEnums(userDto.getRoles());

        // Chain role assignments sequentially
        Mono<User> chain = Mono.just(user);
        for (Roles role : roleEnums) {
            chain = chain.flatMap(u ->
                    roleAssignmentService.assignRoleAndPermissions(u, role)
                            .thenReturn(u)
            );
        }

        return chain
                .flatMap(u -> firebaseServiceAuth.saveUserPermissions(u).thenReturn(u))
                .doOnSuccess(u -> log.info("✅ Roles assigned: {}", u.getRoles()))
                .doOnError(e -> log.error("❌ Failed to assign roles for: {}",
                        user.getEmail(), e));
    }

    /**
     * Sets up regular user with pending approval status.
     */
    private Mono<User> assignRegularUserPermissions(User user) {
        log.info("⚠️ Regular user registration: {}. Pending approval.", user.getEmail());

        return firebaseServiceAuth.saveUserPermissions(user)
                .thenReturn(user)
                .doOnSuccess(u -> log.info("✅ User created with PENDING_APPROVAL status"));
    }

    /**
     * Converts role strings to enum values.
     */
    private List<Roles> convertToRoleEnums(List<String> roleNames) {
        return roleNames.stream()
                .map(roleName -> Roles.fromName(roleName)
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Invalid role: " + roleName)))
                .collect(Collectors.toList());
    }

    /**
     * Persists user data across multiple storage systems.
     */
    private Mono<User> persistUserData(User user, String ipAddress, String deviceFingerprint) {
        return deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint)
                .then(firebaseServiceAuth.saveUser(user, ipAddress, deviceFingerprint))
                .then(metadataService.saveRegistrationMetadata(user, ipAddress))
                .then(cacheUserEmail(user))
                .thenReturn(user);
    }

    /**
     * Caches the registered email (best-effort, non-blocking).
     */
    private Mono<Void> cacheUserEmail(User user) {
        return Mono.fromRunnable(() -> {
            try {
                redisCacheService.cacheRegisteredEmail(user.getEmail())
                        .doOnError(e -> log.warn("Failed to cache email for {}: {}",
                                user.getEmail(), e.getMessage()))
                        .subscribe();
            } catch (Exception ex) {
                log.warn("Cache operation failed for {}: {}", user.getEmail(), ex.getMessage());
            }
        });
    }
}
