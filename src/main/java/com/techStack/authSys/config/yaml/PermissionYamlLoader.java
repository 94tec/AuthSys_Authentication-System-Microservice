package com.techStack.authSys.config.yaml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Provides convenient access to the parsed permissions.yaml config.
 *
 * This is a thin read-only facade over PermissionsYamlConfig. It adds:
 *   - Wildcard resolution  ("*:*", "portfolio:*" → concrete permission names)
 *   - Null-safe accessors  (guards against partially malformed YAML)
 *   - Duplicate detection  (warns on duplicate permission definitions)
 *
 * Used by:
 *   - PermissionSeeder  → writes resolved permissions to Firestore at startup
 *   - Tests             → verifies seeded data matches YAML
 *
 * Import fix from original:
 *   Was importing com.techStack.shared.config.yaml.PermissionsYamlConfig
 *   which does not exist. Corrected to com.techStack.authSys.config.yaml.PermissionsYamlConfig
 *   (same package as this class).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PermissionYamlLoader {

    private final PermissionsYamlConfig config;

    // -------------------------------------------------------------------------
    // Raw config access
    // -------------------------------------------------------------------------

    /**
     * Returns the raw config object.
     * Use for seeding — gives the full structure including categories.
     *
     * @return the bound PermissionsYamlConfig, never null
     *         (Spring will fail at startup if YAML is absent)
     */
    public PermissionsYamlConfig load() {
        return config;
    }

    // -------------------------------------------------------------------------
    // Permission enumeration
    // -------------------------------------------------------------------------

    /**
     * Returns a flat list of all permission full names defined in the YAML.
     * e.g. ["portfolio:view", "portfolio:create", "user:read", ...]
     *
     * Null-safe: skips any namespace or action entry that is null or blank,
     * logging a warning so the YAML author knows something is malformed.
     *
     * Duplicate detection: warns if the same full name appears more than once
     * across namespaces (which would indicate a YAML authoring error).
     *
     * @return unmodifiable list of permission full names, never null
     */
    public List<String> getAllPermissionNames() {
        if (config.getPermissions() == null) {
            log.warn("app.permissions is null — no permissions defined in YAML");
            return Collections.emptyList();
        }

        List<String> names = new ArrayList<>();

        config.getPermissions().forEach((namespace, nsConfig) -> {
            if (namespace == null || namespace.isBlank()) {
                log.warn("Skipping permission namespace with null or blank key");
                return;
            }
            if (nsConfig == null || nsConfig.getActions() == null) {
                log.warn("Namespace '{}' has null config or null actions list — skipping",
                        namespace);
                return;
            }

            nsConfig.getActions().forEach(action -> {
                if (action == null || action.getAction() == null
                        || action.getAction().isBlank()) {
                    log.warn("Namespace '{}' has an action entry with null or blank action — skipping",
                            namespace);
                    return;
                }
                names.add(namespace + ":" + action.getAction());
            });
        });

        // Warn on duplicates — indicates a YAML authoring error
        Set<String> seen = new java.util.HashSet<>();
        names.forEach(name -> {
            if (!seen.add(name)) {
                log.warn("Duplicate permission '{}' found in YAML — check your permissions config",
                        name);
            }
        });

        return Collections.unmodifiableList(names);
    }

    // -------------------------------------------------------------------------
    // Role enumeration
    // -------------------------------------------------------------------------

    /**
     * Returns all role names defined in the role-permissions section of the YAML.
     *
     * @return unmodifiable list of role names, never null
     */
    public List<String> getRoleNames() {
        if (config.getRolePermissions() == null) {
            log.warn("app.role-permissions is null — no roles defined in YAML");
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(
                new ArrayList<>(config.getRolePermissions().keySet()));
    }

    // -------------------------------------------------------------------------
    // Wildcard resolution
    // -------------------------------------------------------------------------

    /**
     * Resolves the permission list for a role, expanding any wildcard entries.
     *
     * Wildcard formats supported:
     *   "*:*"           → all permissions in the YAML (used by SUPER_ADMIN)
     *   "portfolio:*"   → all permissions in the "portfolio" namespace
     *   "portfolio:view" → exactly that one permission (passed through as-is)
     *
     * Returns empty Optional if the role is not defined in the YAML at all,
     * distinguishing "role exists but has no permissions" (present, empty list)
     * from "role not in YAML" (absent). Callers can use this to detect
     * misconfiguration.
     *
     * Deduplicates the result — a role config with both "portfolio:*" and
     * "portfolio:view" will not produce duplicate "portfolio:view" entries.
     *
     * @param roleName the role name as defined in YAML e.g. "ADMIN"
     * @return Optional containing the resolved permission list if the role
     *         is defined, empty Optional if the role is absent from YAML
     */
    public Optional<List<String>> resolvePermissionsForRole(String roleName) {
        if (config.getRolePermissions() == null) {
            log.warn("app.role-permissions is null — cannot resolve permissions for role: {}",
                    roleName);
            return Optional.empty();
        }

        if (!config.getRolePermissions().containsKey(roleName)) {
            log.warn("Role '{}' is not defined in app.role-permissions", roleName);
            return Optional.empty();
        }

        List<String> rawList = config.getRolePermissions().get(roleName);

        if (rawList == null || rawList.isEmpty()) {
            log.debug("Role '{}' is defined in YAML but has an empty permission list", roleName);
            return Optional.of(Collections.emptyList());
        }

        List<String> allPermissions = getAllPermissionNames();
        List<String> resolved       = new ArrayList<>();

        for (String entry : rawList) {
            if (entry == null || entry.isBlank()) {
                log.warn("Role '{}' has a null or blank permission entry — skipping", roleName);
                continue;
            }

            if (entry.equals("*:*")) {
                // SUPER_ADMIN — gets every permission defined in the YAML
                resolved.addAll(allPermissions);
                log.debug("Role '{}' uses *:* wildcard — resolved {} permissions",
                        roleName, allPermissions.size());

            } else if (entry.endsWith(":*")) {
                // Namespace wildcard — e.g. "portfolio:*"
                String namespace = entry.substring(0, entry.length() - 2); // strip ":*"
                if (namespace.isBlank()) {
                    log.warn("Role '{}' has a malformed namespace wildcard '{}' — skipping",
                            roleName, entry);
                    continue;
                }
                String prefix = namespace + ":";
                List<String> matched = allPermissions.stream()
                        .filter(p -> p.startsWith(prefix))
                        .toList();

                if (matched.isEmpty()) {
                    log.warn("Role '{}' wildcard '{}' matched no permissions — " +
                                    "is the namespace '{}' defined in YAML?",
                            roleName, entry, namespace);
                }
                resolved.addAll(matched);

            } else if (entry.contains(":")) {
                // Exact permission — validate it exists in the YAML
                if (!allPermissions.contains(entry)) {
                    log.warn("Role '{}' references permission '{}' which is not defined " +
                                    "in app.permissions — it will still be seeded but may be a typo",
                            roleName, entry);
                }
                resolved.add(entry);

            } else {
                // No colon at all — malformed entry
                log.warn("Role '{}' has permission entry '{}' with no ':' separator — " +
                                "expected format is 'namespace:action'. Skipping.",
                        roleName, entry);
            }
        }

        // Deduplicate while preserving order (LinkedHashSet would reorder;
        // we iterate and track seen instead to preserve first-occurrence order)
        List<String> deduplicated = resolved.stream()
                .distinct()
                .collect(Collectors.toList());

        if (deduplicated.size() != resolved.size()) {
            log.debug("Role '{}' had {} duplicate permission entries removed after wildcard expansion",
                    roleName, resolved.size() - deduplicated.size());
        }

        log.info("Resolved {} permissions for role '{}'", deduplicated.size(), roleName);
        return Optional.of(Collections.unmodifiableList(deduplicated));
    }

    /**
     * Resolves permissions for all roles defined in the YAML.
     *
     * Convenience method for PermissionSeeder — avoids iterating getRoleNames()
     * and calling resolvePermissionsForRole() separately.
     *
     * Roles that return empty Optional from resolvePermissionsForRole()
     * are skipped with a warning (should not happen since we iterate
     * getRoleNames() which comes from the same map, but guards against
     * concurrent modification).
     *
     * @return map of roleName → resolved permission list for all roles in YAML
     */
    public java.util.Map<String, List<String>> resolveAllRolePermissions() {
        java.util.Map<String, List<String>> result = new java.util.LinkedHashMap<>();

        getRoleNames().forEach(roleName ->
                resolvePermissionsForRole(roleName).ifPresentOrElse(
                        perms -> result.put(roleName, perms),
                        () -> log.warn("Skipping role '{}' — could not resolve permissions",
                                roleName)
                )
        );

        return Collections.unmodifiableMap(result);
    }
}