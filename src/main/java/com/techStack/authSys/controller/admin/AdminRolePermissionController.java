package com.techStack.authSys.controller.admin;

import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Admin Role Permission Controller
 *
 * Manages role and permission assignments.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/access")
@RequiredArgsConstructor
public class AdminRolePermissionController {

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PermissionProvider permissionProvider;
    private final Clock clock;

    /* =========================
       Get Roles & Permissions
       ========================= */

    /**
     * Get all roles and their permissions
     */
    @GetMapping("/roles")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getAllRolePermissions() {
        Instant requestTime = clock.instant();

        log.info("Fetching all role permissions at {}", requestTime);

        return Mono.fromCallable(() -> {
            Map<String, Set<String>> rolePermissions = Arrays.stream(Roles.values())
                    .collect(Collectors.toMap(
                            Roles::name,
                            role -> permissionProvider.getPermissionsForRole(role)
                                    .stream()
                                    .map(Enum::name)
                                    .collect(Collectors.toSet())
                    ));

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", rolePermissions,
                    "timestamp", requestTime.toString()
            ));
        });
    }

    /**
     * Get all permissions
     */
    @GetMapping("/permissions")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getAllPermissions() {
        Instant requestTime = clock.instant();

        log.info("Fetching all permissions at {}", requestTime);

        return Mono.fromCallable(() -> {
            Set<String> permissions = Arrays.stream(Permissions.values())
                    .map(Enum::name)
                    .collect(Collectors.toSet());

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", permissions,
                    "timestamp", requestTime.toString()
            ));
        });
    }

    /* =========================
       Role Assignment
       ========================= */

    /**
     * Assign a role to a user
     */
    @PostMapping("/roles/assign")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> assignRoleToUser(
            @RequestParam String userId,
            @RequestParam String roleName) {

        Instant assignmentTime = clock.instant();

        log.info("Assigning role '{}' to user {} at {}", roleName, userId, assignmentTime);

        return Mono.justOrEmpty(Roles.fromName(roleName))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid role name: " + roleName)))
                .flatMap(role -> permissionProvider.assignRole(userId, role)
                        .thenReturn(ResponseEntity.ok(Map.of(
                                "success", true,
                                "message", "Role assigned successfully",
                                "data", Map.of(
                                        "userId", userId,
                                        "role", roleName,
                                        "assignedAt", assignmentTime.toString()
                                )
                        ))))
                .onErrorResume(e -> {
                    log.error("Failed to assign role at {}: {}", assignmentTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(Map.of(
                            "success", false,
                            "message", e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                });
    }

    /* =========================
       Permission Management
       ========================= */

    /**
     * Grant a permission to a user
     */
    @PostMapping("/permissions/grant")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> grantPermissionToUser(
            @RequestParam String userId,
            @RequestParam String permission) {

        Instant grantTime = clock.instant();

        log.info("Granting permission '{}' to user {} at {}", permission, userId, grantTime);

        return Mono.justOrEmpty(Permissions.fromNameSafe(permission))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid permission: " + permission)))
                .doOnNext(perm -> permissionProvider.addPermission(userId, perm))
                .thenReturn(ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Permission granted successfully",
                        "data", Map.of(
                                "userId", userId,
                                "permission", permission,
                                "grantedAt", grantTime.toString()
                        )
                )))
                .onErrorResume(e -> {
                    log.error("Failed to grant permission at {}: {}", grantTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(Map.of(
                            "success", false,
                            "message", e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                });
    }

    /**
     * Revoke a permission from a user
     */
    @PostMapping("/permissions/revoke")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> revokePermissionFromUser(
            @RequestParam String userId,
            @RequestParam String permission) {

        Instant revokeTime = clock.instant();

        log.info("Revoking permission '{}' from user {} at {}", permission, userId, revokeTime);

        return Mono.justOrEmpty(Permissions.fromNameSafe(permission))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid permission: " + permission)))
                .doOnNext(perm -> permissionProvider.removePermission(userId, perm))
                .thenReturn(ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Permission revoked successfully",
                        "data", Map.of(
                                "userId", userId,
                                "permission", permission,
                                "revokedAt", revokeTime.toString()
                        )
                )))
                .onErrorResume(e -> {
                    log.error("Failed to revoke permission at {}: {}", revokeTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(Map.of(
                            "success", false,
                            "message", e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                });
    }

    /* =========================
       Permission Reload
       ========================= */

    /**
     * Reload permissions from YAML
     */
    @PostMapping("/reload")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> reloadPermissions() {
        Instant reloadTime = clock.instant();

        log.warn("🔄 Reloading permissions from YAML at {}", reloadTime);

        return Mono.fromRunnable(permissionProvider::reloadPermissions)
                .thenReturn(ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Permissions reloaded from YAML",
                        "reloadedAt", reloadTime.toString()
                )))
                .onErrorResume(e -> {
                    log.error("Failed to reload permissions at {}: {}", reloadTime, e.getMessage());
                    return Mono.just(ResponseEntity.status(500).body(Map.of(
                            "success", false,
                            "message", "Failed to reload permissions: " + e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                });
    }
}