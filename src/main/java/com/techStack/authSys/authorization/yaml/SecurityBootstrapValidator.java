package com.techStack.authSys.authorization.yaml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.techStack.authSys.authorization.constants.SecurityConstants.VALID_NAMESPACES;

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
            "SUPER_ADMIN", "ADMIN", "OPERATOR", "MANAGER", "USER", "GUEST"
    );
    private static final Pattern WILDCARD_PATTERN =
            Pattern.compile("^\\*:\\*$|^[a-z_]+:\\*$");

    private final PermissionYamlLoader loader;

    public void validate() {
        log.info("🔐 Validating security bootstrap configuration...");

        PermissionsYamlConfig config = loader.load();

        if (config == null) {
            throw new IllegalStateException("permissions.yaml could not be loaded");
        }
        if (config.getPermissions() == null ||
                config.getPermissions().isEmpty()) {

            throw new IllegalStateException(
                    "No permissions defined under authorization.permissions"
            );
        }

        // 1. Namespace validity + blank/null action check + permission-list build,
        //    all done in a single pass so the guards can't drift out of sync.
        List<String> permissions =
                config.getPermissions()
                        .entrySet()
                        .stream()
                        .filter(e -> e.getValue() != null)
                        .flatMap(e -> {

                            String namespace = e.getKey();

                            if (!VALID_NAMESPACES.contains(namespace)) {
                                throw new IllegalStateException(
                                        "Unknown namespace: " + namespace
                                );
                            }

                            if (e.getValue().getActions() == null) {
                                return java.util.stream.Stream.empty();
                            }

                            return e.getValue()
                                    .getActions()
                                    .stream()
                                    .filter(a -> a != null)
                                    .map(a -> {

                                        if (a.getAction() == null || a.getAction().isBlank()) {
                                            throw new IllegalStateException(
                                                    namespace + " contains blank or null action"
                                            );
                                        }

                                        return namespace + ":" + a.getAction();
                                    });
                        })
                        .toList();

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

        Set<String> availablePermissions =
                permissions.stream().collect(Collectors.toSet());

        config.getRolePermissions()
                .forEach((role, perms) -> {

                    if (perms == null) {
                        throw new IllegalStateException(
                                role + " has a null permission list"
                        );
                    }

                    for (String permission : perms) {

                        if (permission == null) {
                            throw new IllegalStateException(
                                    role + " contains a null permission entry"
                            );
                        }

                        if (permission.contains("*")) {

                            if (!WILDCARD_PATTERN.matcher(permission).matches()) {

                                throw new IllegalStateException(
                                        "Invalid wildcard permission: " + permission
                                );

                            }

                            continue;
                        }

                        if (!availablePermissions.contains(permission)) {

                            throw new IllegalStateException(
                                    role +
                                            " references undefined permission " +
                                            permission
                            );

                        }
                    }

                });

        config.getRolePermissions()
                .forEach((role, perms) -> {

                    Set<String> unique = new HashSet<>(perms);

                    if (unique.size() != perms.size()) {

                        throw new IllegalStateException(
                                "Duplicate permissions for role " + role
                        );

                    }

                });
        Set<String> unique = new HashSet<>();

        permissions.forEach(permission -> {

            if (!unique.add(permission)) {

                throw new IllegalStateException(
                        "Duplicate permission found: " + permission
                );

            }

        });

        // 4. All expected roles have mappings
        List<String> missingRoles = REQUIRED_ROLES.stream()
                .filter(role -> !config.getRolePermissions().containsKey(role))
                .toList();

        if (!missingRoles.isEmpty()) {
            throw new IllegalStateException(
                    "Security bootstrap failed: missing role mappings for: " + missingRoles
            );
        }
        config.getRolePermissions()
                .keySet()
                .forEach(role -> {

                    if (!REQUIRED_ROLES.contains(role)) {

                        throw new IllegalStateException(
                                "Unknown role: " + role
                        );

                    }

                });

        log.info("✅ Security bootstrap validation passed — {} permissions, {} roles",
                permissions.size(), config.getRolePermissions().size());
    }
}