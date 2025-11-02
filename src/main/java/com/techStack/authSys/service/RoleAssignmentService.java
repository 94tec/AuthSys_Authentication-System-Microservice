package com.techStack.authSys.service;

import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.AuthRepository;
import com.techStack.authSys.repository.PermissionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static com.techStack.authSys.models.Roles.MANAGER;
import static com.techStack.authSys.models.Roles.USER;

@Service
public class RoleAssignmentService {
    private static final Logger logger = LoggerFactory.getLogger(RoleAssignmentService.class);

    private final PermissionProvider permissionProvider;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final AuthRepository authRepository;
    private final FirebaseClaimsService firebaseClaimsService;

    // Defines registration rules for each role
    private final Map<Roles, RegistrationRule> roleRegistrationRules = new ConcurrentHashMap<>();

    public RoleAssignmentService(PermissionProvider permissionProvider,
                                 FirebaseServiceAuth firebaseServiceAuth,
                                 AuthRepository authRepository,
                                 FirebaseClaimsService firebaseClaimsService) {
        this.permissionProvider = permissionProvider;
        this.firebaseServiceAuth = firebaseServiceAuth;
        this.authRepository = authRepository;
        this.firebaseClaimsService = firebaseClaimsService;
        initializeRegistrationRules();
    }

    private void initializeRegistrationRules() {
        roleRegistrationRules.put(Roles.ADMIN, new RegistrationRule(false, true));     // Admin: no self-reg, requires approval
        roleRegistrationRules.put(MANAGER, new RegistrationRule(true, true));    // Manager: self-reg allowed, requires approval
        roleRegistrationRules.put(USER, new RegistrationRule(true, false));      // User: self-reg allowed, no approval needed
        roleRegistrationRules.put(Roles.SUPER_ADMIN, new RegistrationRule(false, true));
    }

    public Mono<User> processUserRegistration(User user, Set<Roles> requestedRoles,
                                              String ipAddress, String deviceFingerprint) {
        return authRepository.findByEmail(user.getEmail())
                .flatMap(existingUser -> validateRoleUpgrade(existingUser.getRoles(), requestedRoles)
                        .flatMap(valid -> {
                            if (!valid) {
                                return Mono.error(new IllegalArgumentException(
                                        STR."Invalid role upgrade request. Cannot upgrade from \{existingUser.getRoles()} to \{requestedRoles}"));
                            }
                            return processRolesForUser(user, requestedRoles, ipAddress, deviceFingerprint);
                        }))
                .switchIfEmpty(Mono.defer(() -> validateRoleAssignment(user, requestedRoles)
                        .flatMap(valid -> {
                            if (!valid) {
                                return Mono.error(new IllegalArgumentException(
                                        "Invalid role request. Please check if all roles are allowed for self-registration"));
                            }
                            return processRolesForUser(user, requestedRoles, ipAddress, deviceFingerprint);
                        })));
    }

    private Mono<User> processRolesForUser(User user, Set<Roles> requestedRoles,
                                           String ipAddress, String deviceFingerprint) {
        // Convert Set to List for Firestore compatibility
        List<Roles> roleList = new ArrayList<>(requestedRoles);

        return Flux.fromIterable(roleList) // Now iterate over List instead of Set
                .flatMap(role -> {
                    RegistrationRule rule = roleRegistrationRules.get(role);
                    if (rule.requiresApproval()) {
                        return handleApprovalRequired(user, role, ipAddress, deviceFingerprint);
                    } else {
                        return assignRoleAndPermissions(user, role); // Assign role and permissions if no approval required
                    }
                })
                .then(Mono.just(user)); // After all roles are processed, return the updated user
    }

    private Mono<Boolean> validateRoleUpgrade(Set<Roles> currentRoles, Set<Roles> requestedRoles) {
        return Mono.fromCallable(() -> {
            for (Roles requestedRole : requestedRoles) {
                for (Roles currentRole : currentRoles) {
                    if (!requestedRole.hasHigherPrivilegesThan(currentRole) ||
                            !currentRole.canRequestUpgradeTo(requestedRole)) {
                        return false;
                    }
                }
            }
            return true;  // All roles can be upgraded
        });
    }

    private Mono<Boolean> validateRoleAssignment(User user, Set<Roles> requestedRoles) {
        return Mono.fromCallable(() -> {
            if (requestedRoles == null || requestedRoles.isEmpty()) {
                logger.warn("No roles requested by user {}", user.getEmail());
                return false;
            }

            Set<Roles> allowedRoles = getAllowedRolesForUser(user);
            Set<Roles> invalidRoles = requestedRoles.stream()
                    .filter(role -> !allowedRoles.contains(role))
                    .collect(Collectors.toSet());

            if (!invalidRoles.isEmpty()) {
                logger.warn("🚫 Invalid roles requested by [{}]: {}. Allowed roles: {}",
                        user.getEmail(), invalidRoles, allowedRoles);
                return false;
            }

            for (Roles role : requestedRoles) {
                RegistrationRule rule = roleRegistrationRules.get(role);
                if (rule == null) {
                    logger.warn("Non-existent role [{}] requested by {}", role, user.getEmail());
                    return false;
                }
                if (!rule.allowSelfRegistration()) {
                    logger.warn("⚠️ Role [{}] not allowed for self-registration by {}", role, user.getEmail());
                    return false;
                }
            }

            return true;
        });
    }
    private Set<Roles> getAllowedRolesForUser(User user) {
        return roleRegistrationRules.entrySet().stream()
                .filter(entry -> entry.getValue().allowSelfRegistration())
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    private Mono<User> handleApprovalRequired(User user, Roles requestedRole, String ipAddress, String deviceFingerprint) {
        user.setStatus(User.Status.PENDING_APPROVAL);
        user.setRequestedRole(requestedRole);

        return firebaseServiceAuth.saveUser(user, ipAddress, deviceFingerprint)
                .doOnSuccess(savedUser -> logger.info("Approval required for user {} requesting role {}", savedUser.getId(), requestedRole));
    }

    public Mono<User> assignRoleAndPermissions(User user, Roles role) {
        user.addRole(role);  // Add the role to the user's roles
        //user.setStatus(User.Status.ACTIVE);

        return permissionProvider.assignRole(user.getId(), role)
                .then(Mono.fromRunnable(() -> addDefaultAttributes(user, role)))
                .then(Mono.just(user))
                .flatMap(u -> firebaseClaimsService.setClaimsReactive(u.getId(), role).thenReturn(u))
                .doOnSuccess(u -> logger.info("Assigned role {} to user {}", role, u.getId()))
                .onErrorResume(e -> {
                    logger.error("Error during role assignment for user {}: {}", user.getId(), e.getMessage());
                    return Mono.error(new RuntimeException("Role assignment failed"));
                });
    }

    private void addDefaultAttributes(User user, Roles role) {
        if (user.getDepartment() != null && !user.getDepartment().isEmpty()) {
            permissionProvider.addUserAttribute(user.getId(), "department", user.getDepartment(), "system");
        }

        switch (role) {
            case MANAGER -> permissionProvider.addUserAttribute(user.getId(), "access_level", "manager", "system");
            case USER ->permissionProvider.addUserAttribute(user.getId(), "access_level", "standard", "system");
        }
    }
    public Mono<User> approveRoleRequest(String userId) {
        return authRepository.findById(userId)
                .flatMap(user -> {
                    if (user.getStatus() != User.Status.PENDING_APPROVAL) {
                        return Mono.error(new IllegalStateException("User is not pending approval"));
                    }
                    if (user.getRoles() == null || user.getRoles().isEmpty()) {
                        return Mono.error(new IllegalStateException("No role requested for approval"));
                    }

                    // Iterate over the Set of Roles and assign each role and permissions
                    return Flux.fromIterable(user.getRoles())
                            .flatMap(role -> assignRoleAndPermissions(user, role))
                            .then(Mono.just(user)); // Return the updated user after processing all roles
                });
    }

    private static class RegistrationRule {
        private final boolean allowSelfRegistration;
        private final boolean requiresApproval;

        public RegistrationRule(boolean allowSelfRegistration, boolean requiresApproval) {
            this.allowSelfRegistration = allowSelfRegistration;
            this.requiresApproval = requiresApproval;
        }

        public boolean allowSelfRegistration() {
            return allowSelfRegistration;
        }

        public boolean requiresApproval() {
            return requiresApproval;
        }
    }
}
