package com.techStack.authSys.config.yaml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * Validates permissions.yaml is coherent before seeding.
 * Throws IllegalStateException on startup if validation fails —
 * intentionally hard-fails rather than silently continuing with
 * a broken permission set.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityBootstrapValidator {

    private static final Set<String> REQUIRED_PERMISSIONS = Set.of(
            // Auth core
            "user:read", "user:update",
            // Tour module
            "tour:view", "tour:create", "tour:update", "tour:publish",
            // Booking module
            "booking:create", "booking:view_own", "booking:view_all",
            "booking:confirm", "booking:cancel_own", "booking:cancel_any",
            // Payment module
            "payment:process", "payment:view_own"
    );

    private static final Set<String> REQUIRED_ROLES = Set.of(
            "SUPER_ADMIN", "ADMIN", "DESIGNER", "MANAGER", "USER", "GUEST"
    );

    private final PermissionYamlLoader loader;

    public void validate() {
        log.info("🔐 Validating security bootstrap configuration...");

        PermissionsYamlConfig config = loader.load();

        // 1. Permissions not empty
        List<String> permissions = config.getPermissions()
                .stream()
                .map(PermissionsYamlConfig.PermissionDef::getName)
                .toList();

        if (permissions.isEmpty()) {
            throw new IllegalStateException(
                    "Security bootstrap failed: permissions.yaml has no permissions defined"
            );
        }

        // 2. All required permissions present
        List<String> missing = REQUIRED_PERMISSIONS.stream()
                .filter(req -> !permissions.contains(req))
                .toList();

        if (!missing.isEmpty()) {
            throw new IllegalStateException(
                    "Security bootstrap failed: missing required permissions: " + missing
            );
        }

        // 3. Role mappings not empty
        if (config.getRolePermissions() == null || config.getRolePermissions().isEmpty()) {
            throw new IllegalStateException(
                    "Security bootstrap failed: no role-permission mappings defined"
            );
        }

        // 4. All expected roles have mappings
        List<String> missingRoles = REQUIRED_ROLES.stream()
                .filter(role -> !config.getRolePermissions().containsKey(role))
                .toList();

        if (!missingRoles.isEmpty()) {
            throw new IllegalStateException(
                    "Security bootstrap failed: missing role mappings for: " + missingRoles
            );
        }

        log.info("✅ Security bootstrap validation passed — {} permissions, {} roles",
                permissions.size(), config.getRolePermissions().size());
    }
}