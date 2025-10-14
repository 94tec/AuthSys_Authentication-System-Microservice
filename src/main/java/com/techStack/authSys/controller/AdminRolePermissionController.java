package com.techStack.authSys.controller;

import com.techStack.authSys.models.Permissions;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.repository.AuthRepository;
import com.techStack.authSys.repository.PermissionProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/access")
@RequiredArgsConstructor
public class AdminRolePermissionController {

    private final AuthRepository authRepository;
    private final PermissionProvider permissionProvider;

    // 1. Get all roles and their permissions
    @GetMapping("/roles")
    public Mono<Map<String, Set<String>>> getAllRolePermissions() {
        return Mono.just(
                Arrays.stream(Roles.values())
                        .collect(Collectors.toMap(
                                Roles::name,
                                role -> permissionProvider.getPermissionsForRole(role)
                                        .stream()
                                        .map(Enum::name)
                                        .collect(Collectors.toSet())
                        ))
        );
    }

    // 2. Get all permissions
    @GetMapping("/permissions")
    public Mono<Set<String>> getAllPermissions() {
        return Mono.just(
                Arrays.stream(Permissions.values())
                        .map(Enum::name)
                        .collect(Collectors.toSet())
        );
    }

    // 3. Assign a role to a user
    @PostMapping("/roles/assign")
    public Mono<ResponseEntity<String>> assignRoleToUser(
            @RequestParam String userId,
            @RequestParam String roleName) {

        return Mono.justOrEmpty(Roles.fromName(roleName))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid role name")))
                .flatMap(role -> permissionProvider.assignRole(userId, role)
                        .thenReturn(ResponseEntity.ok("Role assigned")))
                .onErrorResume(e -> Mono.just(ResponseEntity.badRequest().body(e.getMessage())));
    }

    // 4. Grant a permission to a user
    @PostMapping("/permissions/grant")
    public Mono<ResponseEntity<String>> grantPermissionToUser(
            @RequestParam String userId,
            @RequestParam String permission) {

        return Mono.justOrEmpty(Permissions.fromNameSafe(permission))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid permission")))
                .doOnNext(perm -> permissionProvider.addPermission(userId, perm))
                .thenReturn(ResponseEntity.ok("Permission granted"))
                .onErrorResume(e -> Mono.just(ResponseEntity.badRequest().body(e.getMessage())));
    }

    // 5. Revoke a permission from a user
    @PostMapping("/permissions/revoke")
    public Mono<ResponseEntity<String>> revokePermissionFromUser(
            @RequestParam String userId,
            @RequestParam String permission) {

        return Mono.justOrEmpty(Permissions.fromNameSafe(permission))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid permission")))
                .doOnNext(perm -> permissionProvider.removePermission(userId, perm))
                .thenReturn(ResponseEntity.ok("Permission revoked"))
                .onErrorResume(e -> Mono.just(ResponseEntity.badRequest().body(e.getMessage())));
    }

    // 6. Reload permissions from YAML
    @PostMapping("/reload")
    public Mono<ResponseEntity<String>> reloadPermissions() {
        return Mono.fromRunnable(permissionProvider::reloadPermissions)
                .thenReturn(ResponseEntity.ok("Permissions reloaded from YAML"));
    }
}
