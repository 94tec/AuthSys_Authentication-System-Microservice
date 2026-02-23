package com.techStack.authSys.service.authorization;

import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.authorization.FirestoreRolePermissionsRepository;
import com.techStack.authSys.repository.authorization.FirestoreUserPermissionsRepository;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Permission Service
 *
 * Manages role-based and user-specific permissions.
 * Implements Fine-Grained Authorization (FGA) with RBAC and ABAC support.
 *
 * Migration note — v1 vs v2:
 *   The original service was the sole authority on permissions, using an
 *   in-memory ConcurrentHashMap of enum-based Permissions values loaded
 *   from a PermissionsConfig YAML. This created two parallel systems:
 *   the enum cache here and the Firestore-backed string permission system
 *   in FirestoreRolePermissionsRepository / FirestoreUserPermissionsRepository.
 *
 *   This version delegates all role-permission lookups to
 *   FirestoreRolePermissionsRepository (which reads from role_permissions/
 *   seeded by PermissionSeeder) and all user-permission reads/writes to
 *   FirestoreUserPermissionsRepository. The in-memory enum cache is removed.
 *
 *   ABAC user attributes are retained in-memory (ConcurrentHashMap) because
 *   they are ephemeral session-scoped data, not persisted state.
 *
 *   The PermissionProvider interface methods that referenced the old
 *   Permissions enum are implemented here via string-based equivalents.
 *   Callers that still use the enum-based API should migrate to strings.
 */
@Service
@RequiredArgsConstructor
public class PermissionService implements PermissionProvider {

    private static final Logger logger = LoggerFactory.getLogger(PermissionService.class);

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private final FirestoreRolePermissionsRepository rolePermissionsRepository;
    private final FirestoreUserPermissionsRepository userPermissionsRepository;

    // -------------------------------------------------------------------------
    // In-memory ABAC attribute store
    //
    // Attributes are ephemeral — set at login/registration time, not persisted.
    // Structure: userId → namespace → key → value
    // -------------------------------------------------------------------------

    private final Map<String, Map<String, Map<String, String>>> userAttributes =
            new ConcurrentHashMap<>();

    // -------------------------------------------------------------------------
    // Role-based permissions
    // -------------------------------------------------------------------------

    /**
     * Returns all permission strings for a given role.
     *
     * Delegates to FirestoreRolePermissionsRepository which reads from
     * role_permissions/{roleName} seeded by PermissionSeeder.
     *
     * Result is cached by the repository layer under "rolePermissions".
     *
     * @param role the role enum value
     * @return set of permission full names e.g. {"portfolio:view", "user:read"}
     */
    @Override
    @Cacheable(value = "rolePermissions", key = "#role.name()")
    public Set<String> getPermissionsForRole(Roles role) {
        List<String> permissions = rolePermissionsRepository
                .findByRoleNameBlocking(role.name());

        logger.debug("Retrieved {} permissions for role {}", permissions.size(), role);
        return new HashSet<>(permissions);
    }

    /**
     * Assigns a role to a user by updating their FirestoreUserPermissions document.
     *
     * Evicts the effectivePermissions cache for this user so the next
     * resolveEffectivePermissions() call reloads from Firestore.
     *
     * @param userId the user's Firebase UID
     * @param role   the role to assign
     * @return Mono completing when the Firestore write is done
     */
    @Override
    @CacheEvict(value = "effectivePermissions", key = "#userId")
    public Mono<Void> assignRole(String userId, Roles role) {
        return userPermissionsRepository.findByFirebaseUid(userId)
                .switchIfEmpty(Mono.defer(() ->
                        userPermissionsRepository.createDefault(userId)))
                .flatMap(userPerms -> {
                    userPerms.addRole(role.name());
                    return userPermissionsRepository.save(userPerms);
                })
                .doOnSuccess(saved ->
                        logger.info("✅ Role {} assigned to user {} in Firestore",
                                role.name(), userId))
                .doOnError(e ->
                        logger.error("❌ Error assigning role {} to user {}: {}",
                                role, userId, e.getMessage(), e))
                .onErrorMap(e -> new RuntimeException(
                        "Role assignment failed for user " + userId + ": " + e.getMessage(), e))
                .then();
    }

    // -------------------------------------------------------------------------
    // Permission checking
    // -------------------------------------------------------------------------

    /**
     * Checks whether a user has a specific permission.
     *
     * Resolution order:
     *   1. Load user's FirestoreUserPermissions (roles, grants, denials)
     *   2. Resolve role permissions for each role from FirestoreRolePermissionsRepository
     *   3. Apply grants (add) and denials (remove — denials always win)
     *   4. Check if requiredPermission is in the result set
     *
     * @param userId             the user's Firebase UID
     * @param requiredPermission full permission name e.g. "portfolio:publish"
     * @return Mono<Boolean> true if the user has the permission
     */
    public Mono<Boolean> hasPermission(String userId, String requiredPermission) {
        if (userId == null || userId.isBlank()
                || requiredPermission == null || requiredPermission.isBlank()) {
            return Mono.just(false);
        }

        return userPermissionsRepository.findByFirebaseUid(userId)
                .flatMap(userPerms ->
                        rolePermissionsRepository
                                .resolveForRoles(userPerms.getRoles())
                                .map(rolePerms -> {
                                    Set<String> effective = new HashSet<>(rolePerms);
                                    effective.addAll(userPerms.getGrants());
                                    effective.removeAll(userPerms.getDenials());
                                    return effective.contains(requiredPermission);
                                })
                )
                .switchIfEmpty(Mono.just(false))
                .doOnError(e -> logger.error(
                        "Error checking permission {} for user {}: {}",
                        requiredPermission, userId, e.getMessage(), e))
                .onErrorReturn(false)
                .subscribeOn(Schedulers.boundedElastic());
    }

    // -------------------------------------------------------------------------
    // Effective permissions resolution
    // -------------------------------------------------------------------------

    /**
     * Resolves the complete set of effective permission strings for a user.
     *
     * Algorithm:
     *   1. Start with role-based permissions from FirestoreRolePermissionsRepository
     *   2. Add user-specific additionalPermissions from the User entity
     *   3. (Grants and denials from FirestoreUserPermissions are applied by
     *      AuthService at JWT generation time — not here, to avoid a second
     *      Firestore read in contexts where we only have the User object)
     *
     * @param user the user entity
     * @return set of effective permission strings
     */
    @Override
    @Cacheable(value = "effectivePermissions", key = "#user.email")
    public Set<String> resolveEffectivePermissions(User user) {
        Set<String> effective = new HashSet<>();

        // 1. Add user-specific additional permissions
        if (user.getAdditionalPermissions() != null) {
            effective.addAll(user.getAdditionalPermissions());
        }

        // 2. Add role-based permissions from Firestore
        if (user.getRoleNames() != null && !user.getRoleNames().isEmpty()) {
            for (String roleName : user.getRoleNames()) {
                Roles.fromName(roleName).ifPresentOrElse(
                        role -> {
                            Set<String> rolePerms = getPermissionsForRole(role);
                            effective.addAll(rolePerms);
                            logger.debug("Added {} permissions from role {} for user {}",
                                    rolePerms.size(), role, user.getId());
                        },
                        () -> logger.warn("⚠️ Unknown role [{}] for user [{}] — skipping",
                                roleName, user.getId())
                );
            }
        } else {
            logger.warn("⚠️ No roles found for user {}", user.getEmail());
        }

        logger.info("✅ Resolved {} effective permissions for user {}",
                effective.size(), user.getEmail());

        return Collections.unmodifiableSet(effective);
    }

    /**
     * Alias for resolveEffectivePermissions — satisfies PermissionProvider interface.
     */
    @Override
    public Set<String> resolveEffectivePermission(User user) {
        return resolveEffectivePermissions(user);
    }

    // -------------------------------------------------------------------------
    // User-specific permission management
    // -------------------------------------------------------------------------

    /**
     * Adds an explicit permission grant to a user's FirestoreUserPermissions document.
     * Evicts the effectivePermissions cache for this user.
     *
     * @param userId     the user's Firebase UID
     * @param permission full permission name e.g. "portfolio:publish"
     */
    @Override
    @CacheEvict(value = "effectivePermissions", key = "#userId")
    public void addPermission(String userId, String permission) {
        userPermissionsRepository.findByFirebaseUid(userId)
                .switchIfEmpty(Mono.defer(() ->
                        userPermissionsRepository.createDefault(userId)))
                .flatMap(userPerms -> {
                    userPerms.grant(permission);
                    return userPermissionsRepository.save(userPerms);
                })
                .doOnSuccess(v ->
                        logger.info("Permission {} granted to user {}", permission, userId))
                .doOnError(e ->
                        logger.error("Failed to grant permission {} to user {}: {}",
                                permission, userId, e.getMessage(), e))
                .subscribeOn(Schedulers.boundedElastic())
                .subscribe();
    }

    /**
     * Adds an explicit permission denial to a user's FirestoreUserPermissions document.
     * Evicts the effectivePermissions cache for this user.
     *
     * @param userId     the user's Firebase UID
     * @param permission full permission name e.g. "system:backup"
     */
    @Override
    @CacheEvict(value = "effectivePermissions", key = "#userId")
    public void removePermission(String userId, String permission) {
        userPermissionsRepository.findByFirebaseUid(userId)
                .flatMap(userPerms -> {
                    userPerms.deny(permission);
                    return userPermissionsRepository.save(userPerms);
                })
                .doOnSuccess(v ->
                        logger.info("Permission {} denied for user {}", permission, userId))
                .doOnError(e ->
                        logger.error("Failed to deny permission {} for user {}: {}",
                                permission, userId, e.getMessage(), e))
                .subscribeOn(Schedulers.boundedElastic())
                .subscribe();
    }

    // -------------------------------------------------------------------------
    // ABAC: Attribute-Based Access Control
    // -------------------------------------------------------------------------

    /**
     * Checks whether a user has the required permission AND the required
     * resource attributes match the user's stored attributes.
     *
     * @param userId             the user's Firebase UID
     * @param requiredPermission full permission name
     * @param resourceAttributes map of "namespace:key" → required value
     * @return Mono<Boolean> true if both permission and attribute checks pass
     */
    public Mono<Boolean> hasPermissionWithAttributes(
            String userId,
            String requiredPermission,
            Map<String, String> resourceAttributes
    ) {
        return Mono.zip(
                hasPermission(userId, requiredPermission),
                checkAttributes(userId, resourceAttributes)
        ).map(tuple -> tuple.getT1() && tuple.getT2());
    }

    /**
     * Verifies that a user's stored attributes match the required resource attributes.
     *
     * @param userId             the user's Firebase UID
     * @param resourceAttributes map of "namespace:key" → required value
     * @return Mono<Boolean> true if all attribute requirements are satisfied
     */
    private Mono<Boolean> checkAttributes(
            String userId,
            Map<String, String> resourceAttributes
    ) {
        if (resourceAttributes == null || resourceAttributes.isEmpty()) {
            return Mono.just(true);
        }

        return Mono.justOrEmpty(userAttributes.get(userId))
                .map(userAttrNamespaces ->
                        resourceAttributes.entrySet().stream().allMatch(entry -> {
                            String[] parts = entry.getKey().split(":", 2);
                            if (parts.length != 2) {
                                logger.warn("Malformed resource attribute key '{}' — expected namespace:key",
                                        entry.getKey());
                                return false;
                            }
                            String namespace = parts[0];
                            String key       = parts[1];

                            return userAttrNamespaces
                                    .getOrDefault(namespace, Map.of())
                                    .getOrDefault(key, "")
                                    .equals(entry.getValue());
                        }))
                .defaultIfEmpty(false)
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Stores a user attribute for ABAC evaluation.
     *
     * Attributes are stored in-memory only — they are set at login/registration
     * time and lost on restart. They are not persisted to Firestore.
     *
     * @param userId    the user's Firebase UID
     * @param namespace attribute namespace e.g. "department"
     * @param key       attribute key e.g. "name"
     * @param value     attribute value e.g. "engineering"
     */
    @Override
    public void addUserAttribute(String userId, String namespace, String key, String value) {
        userAttributes
                .computeIfAbsent(userId,    k -> new ConcurrentHashMap<>())
                .computeIfAbsent(namespace, k -> new ConcurrentHashMap<>())
                .put(key, value);

        logger.debug("Added user attribute: {} {}:{}={}", userId, namespace, key, value);
    }

    // -------------------------------------------------------------------------
    // PermissionProvider interface — string-based implementations
    // -------------------------------------------------------------------------

    /**
     * Returns all permission full names known to the system.
     * Reads from all role_permissions documents and unions the results.
     */
    @Override
    public String[] getPermissions() {
        // Collect all known permissions across all roles
        List<String> allRoles = List.of(
                Roles.SUPER_ADMIN.name(), Roles.ADMIN.name(),
                Roles.MANAGER.name(), Roles.USER.name());

        return rolePermissionsRepository
                .resolveForRolesBlocking(allRoles)
                .toArray(String[]::new);
    }

    /**
     * Returns all permission full names within a given namespace prefix.
     * e.g. getSubPermissions("portfolio") → ["portfolio:view", "portfolio:publish", ...]
     *
     * @param namespace the namespace prefix (without colon)
     * @return array of matching permission full names
     */
    @Override
    public String[] getSubPermissions(String namespace) {
        if (namespace == null || namespace.isBlank()) return new String[0];

        String prefix = namespace + ":";
        return Arrays.stream(getPermissions())
                .filter(p -> p.startsWith(prefix))
                .toArray(String[]::new);
    }

    /**
     * Returns the loaded role → permissions mapping.
     * Used for diagnostics and admin endpoints.
     */
    @Override
    public Object getLoadedRoles() {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (Roles role : Roles.values()) {
            result.put(role.name(),
                    rolePermissionsRepository.findByRoleNameBlocking(role.name()));
        }
        return result;
    }

    /**
     * Evicts all permission caches and clears in-memory ABAC attributes.
     * Call this after PermissionSeeder re-seeds Firestore.
     */
    @Override
    @CacheEvict(value = {"rolePermissions", "effectivePermissions"}, allEntries = true)
    public void reloadPermissions() {
        userAttributes.clear();
        rolePermissionsRepository.evictCache();
        logger.info("✅ Permission caches evicted — next reads will reload from Firestore");
    }

    /**
     * Deserializes a list of permission strings, filtering out any blank entries.
     * Logs a warning for each blank entry encountered.
     *
     * @param permissions list of permission full name strings
     * @return filtered list of non-blank permission strings
     */
    @Override
    public List<String> deserializePermissions(List<String> permissions) {
        if (permissions == null || permissions.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> result = new ArrayList<>();
        for (String permission : permissions) {
            if (permission == null || permission.isBlank()) {
                logger.warn("⚠️ Null or blank permission string encountered during deserialization");
                continue;
            }
            if (!permission.contains(":")) {
                logger.warn("⚠️ Permission '{}' has no ':' separator — expected namespace:action format",
                        permission);
            }
            result.add(permission);
        }

        return Collections.unmodifiableList(result);
    }
}