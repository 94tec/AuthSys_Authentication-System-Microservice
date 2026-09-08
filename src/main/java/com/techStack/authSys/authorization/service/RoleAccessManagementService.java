package com.techStack.authSys.authorization.service;

import com.techStack.authSys.authorization.exception.AccessDeniedException;
import com.techStack.authSys.authorization.models.RolePermissionOverride;
import com.techStack.authSys.authorization.repository.PermissionProvider;
import com.techStack.authSys.authorization.repository.RolePermissionOverrideRepository;
import com.techStack.authSys.common.cache.RedisUserCacheService;
import com.techStack.authSys.authorization.models.Roles;
import com.techStack.authSys.identity.models.User;
import com.techStack.authSys.identity.repository.FirestoreUserRepository;
import com.techStack.authSys.security.audit.ActionType;
import com.techStack.authSys.security.audit.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.util.*;
import java.util.stream.Collectors;

/**
 * SUPER_ADMIN-only role & permission management.
 *
 * Two capabilities:
 * 1. Permission overrides — grant/revoke individual permissions per role
 *    without redeploying (persisted, layered on top of PermissionProvider's
 *    hard-coded defaults).
 * 2. Safe role reassignment — change a user's role with guardrails so the
 *    platform can never be left with zero SUPER_ADMIN accounts, and so
 *    SUPER_ADMIN's own permission set can never be edited away (it must
 *    always retain full access as the recovery path of last resort).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RoleAccessManagementService {

    private final PermissionProvider permissionProvider;
    private final RolePermissionOverrideRepository overrideRepository;
    private final FirestoreUserRepository userRepository;
    private final RedisUserCacheService cacheService;
    private final AuditLogService auditLogService;
    private final Clock clock;

    /* =========================
       PERMISSION OVERRIDES
       ========================= */

    public Mono<Set<String>> getEffectivePermissionsForRole(Roles role) {
        return Mono.fromCallable(() -> permissionProvider.getEffectivePermissionsForRole(role))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<RolePermissionOverride> setPermissionOverride(
            Roles role, String permission, boolean granted, String setBy, String reason) {

        if (role == Roles.SUPER_ADMIN) {
            return Mono.error(AccessDeniedException.operationNotAllowed(
                    "modify SUPER_ADMIN permissions", "SUPER_ADMIN role is fixed and cannot be overridden"));
        }

        return Mono.fromCallable(() -> {
                    RolePermissionOverride override = overrideRepository
                            .findByRoleAndPermission(role, permission)
                            .orElseGet(() -> RolePermissionOverride.builder()
                                    .role(role)
                                    .permission(permission)
                                    .build());
                    override.setGranted(granted);
                    override.setSetBy(setBy);
                    override.setReason(reason);
                    RolePermissionOverride saved = overrideRepository.save(override);

                    auditLogService.logAuditEvent(
                            setBy, ActionType.PERMISSIONS_GRANTED,
                            String.format("%s permission '%s' for role %s",
                                    granted ? "Granted" : "Revoked", permission, role),
                            Map.of("role", role.name(), "permission", permission, "granted", granted)
                    ).subscribe();

                    return saved;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> permissionProvider.evictEffectiveRolePermissionsCache(role));
    }

    public Mono<Void> removeOverride(Roles role, String permission) {
        return Mono.fromRunnable(() -> overrideRepository.deleteByRoleAndPermission(role, permission))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> permissionProvider.evictEffectiveRolePermissionsCache(role))
                .then();
    }

    public Flux<RolePermissionOverride> getOverridesForRole(Roles role) {
        return Mono.fromCallable(() -> overrideRepository.findByRole(role))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /* =========================
       SAFE ROLE REASSIGNMENT
       ========================= */

    /**
     * Change a user's role. Guardrails:
     * - Only SUPER_ADMIN may call this (enforced at controller via @PreAuthorize too — belt & suspenders).
     * - Cannot demote the last remaining SUPER_ADMIN account.
     * - Cannot assign SUPER_ADMIN except by an existing SUPER_ADMIN (defense in depth beyond @PreAuthorize).
     * - Every change is audited with old role -> new role.
     */
    public Mono<User> changeUserRole(String targetUserId, Roles newRole, String performerId, Roles performerRole) {
        if (performerRole != Roles.SUPER_ADMIN) {
            return Mono.error(AccessDeniedException.insufficientRole("SUPER_ADMIN", performerRole.name()));
        }

        return userRepository.findById(targetUserId)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("User not found: " + targetUserId)))
                .flatMap(user -> {
                    Set<Roles> currentRoles = user.getRoles();
                    boolean isDemotingLastSuperAdmin = currentRoles.contains(Roles.SUPER_ADMIN)
                            && newRole != Roles.SUPER_ADMIN;

                    Mono<Boolean> guardCheck = isDemotingLastSuperAdmin
                            ? countActiveSuperAdmins().map(count -> count > 1)
                            : Mono.just(true);

                    return guardCheck.flatMap(safe -> {
                        if (!safe) {
                            return Mono.error(new IllegalStateException(
                                    "Cannot demote the last remaining SUPER_ADMIN account. " +
                                            "Create/promote another SUPER_ADMIN first."));
                        }

                        Set<Roles> oldRoles = new HashSet<>(currentRoles);
                        user.setRoleNames(List.of(newRole.name()));
                        user.setUpdatedAt(clock.instant());

                        return userRepository.update(user)
                                .flatMap(saved -> cacheService.invalidateUserPermissions(saved.getId())
                                        .then(logRoleChange(saved.getId(), oldRoles, newRole, performerId))
                                        .thenReturn(saved));
                    });
                });
    }

    private Mono<Long> countActiveSuperAdmins() {
        return userRepository.findByRole(Roles.SUPER_ADMIN)
                .filter(User::isEnabled)
                .count();
    }

    private Mono<Void> logRoleChange(String userId, Set<Roles> oldRoles, Roles newRole, String performerId) {
        return Mono.fromRunnable(() ->
                auditLogService.logAuditEvent(
                        userId, ActionType.PERMISSIONS_GRANTED,
                        "Role changed by " + performerId,
                        Map.of(
                                "oldRoles", oldRoles.stream().map(Enum::name).collect(Collectors.toSet()),
                                "newRole", newRole.name(),
                                "performedBy", performerId,
                                "timestamp", clock.instant().toString()
                        )
                ).subscribe()
        );
    }
}
