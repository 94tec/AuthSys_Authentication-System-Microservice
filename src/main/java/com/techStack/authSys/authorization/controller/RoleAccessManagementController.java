package com.techStack.authSys.authorization.controller;

import com.techStack.authSys.authorization.models.RolePermissionOverride;
import com.techStack.authSys.authorization.service.RoleAccessManagementService;
import com.techStack.authSys.authorization.models.Roles;
import com.techStack.authSys.identity.models.User;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * SUPER_ADMIN: Role management + Permission management.
 * Everything here is behind hasRole('SUPER_ADMIN') — no other role may
 * view or alter role/permission configuration for the platform.
 */
@RestController
@RequestMapping("/api/admin/access")
@RequiredArgsConstructor
@PreAuthorize("hasRole('SUPER_ADMIN')")
public class RoleAccessManagementController {

    private final RoleAccessManagementService accessService;

    // ── Permission inspection ────────────────────────────────────────────────

    @GetMapping("/roles/{role}/permissions")
    public Mono<ResponseEntity<Set<String>>> getEffectivePermissions(@PathVariable Roles role) {
        return accessService.getEffectivePermissionsForRole(role).map(ResponseEntity::ok);
    }

    @GetMapping("/roles/{role}/overrides")
    public Flux<RolePermissionOverride> getOverrides(@PathVariable Roles role) {
        return accessService.getOverridesForRole(role);
    }

    // ── Permission overrides ─────────────────────────────────────────────────

    @PostMapping("/roles/{role}/permissions")
    public Mono<ResponseEntity<RolePermissionOverride>> setOverride(
            @PathVariable Roles role,
            @RequestBody PermissionOverrideRequest request,
            @RequestHeader("X-User-Id") String setBy
    ) {
        return accessService.setPermissionOverride(
                        role, request.getPermission(), request.isGranted(), setBy, request.getReason())
                .map(ResponseEntity::ok);
    }

    @DeleteMapping("/roles/{role}/permissions/{permission}")
    public Mono<ResponseEntity<Void>> removeOverride(
            @PathVariable Roles role,
            @PathVariable String permission
    ) {
        return accessService.removeOverride(role, permission)
                .then(Mono.just(ResponseEntity.noContent().build()));
    }

    // ── Role reassignment (with last-SUPER_ADMIN guard) ──────────────────────

    @PostMapping("/users/{userId}/role")
    public Mono<ResponseEntity<User>> changeUserRole(
            @PathVariable String userId,
            @RequestBody ChangeRoleRequest request,
            @RequestHeader("X-User-Id") String performerId
    ) {
        return accessService.changeUserRole(userId, request.getNewRole(), performerId, Roles.SUPER_ADMIN)
                .map(ResponseEntity::ok);
    }

    @Data
    public static class PermissionOverrideRequest {
        private String permission;
        private boolean granted;
        private String reason;
    }

    @Data
    public static class ChangeRoleRequest {
        private Roles newRole;
    }
}
