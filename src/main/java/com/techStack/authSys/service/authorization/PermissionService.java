package com.techStack.authSys.service.authorization;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.*;
import com.techStack.authSys.config.security.PermissionsConfig;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import javax.annotation.PostConstruct;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Permission Service
 *
 * Manages role-based and user-specific permissions with caching.
 * Implements Fine-Grained Authorization (FGA) with RBAC and ABAC support.
 */
@Service
@RequiredArgsConstructor
public class PermissionService implements PermissionProvider {

    private static final Logger logger = LoggerFactory.getLogger(PermissionService.class);

    /* =========================
       Dependencies
       ========================= */

    private final PermissionsConfig permissionsConfig;
    private final Firestore firestore;
    private final Clock clock;

    /* =========================
       In-Memory Caches
       ========================= */

    private final Map<String, Set<Permissions>> userPermissions = new ConcurrentHashMap<>();
    private final Map<Roles, Set<Permissions>> rolePermissions = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Map<String, String>>> userAttributes = new ConcurrentHashMap<>();

    /* =========================
       Initialization
       ========================= */

    @PostConstruct
    public void init() {
        reloadPermissions();
        logger.info("✅ PermissionService initialized with {} role configurations",
                rolePermissions.size());
    }

    /* =========================
       Role-Based Permissions
       ========================= */

    @Override
    @Cacheable(value = "rolePermissions", key = "#role.name()")
    public Set<Permissions> getPermissionsForRole(Roles role) {
        Set<Permissions> permissions = rolePermissions.getOrDefault(role, Collections.emptySet());
        logger.debug("Retrieved {} permissions for role {}", permissions.size(), role);
        return new HashSet<>(permissions); // Return copy to prevent modification
    }

    @Override
    @CacheEvict(value = {"rolePermissions", "effectivePermissions"}, allEntries = true)
    public Mono<Void> assignRole(String userId, Roles role) {
        return Mono.defer(() -> {
            Instant now = clock.instant();

            try {
                Set<Permissions> permissions = getPermissionsForRole(role);

                // Update in-memory cache
                userPermissions.put(userId, new HashSet<>(permissions));

                logger.info("✅ Role {} assigned to user {} with {} permissions",
                        role, userId, permissions.size());

                // Prepare Firestore data
                Map<String, Object> roleData = Map.of(
                        "userId", userId,
                        "role", role.name(),
                        "permissions", permissions.stream()
                                .map(Permissions::name)
                                .collect(Collectors.toList()),
                        "assignedAt", now
                );

                // Persist to Firestore
                DocumentReference roleRef = firestore
                        .collection("users")
                        .document(userId)
                        .collection("user_roles")
                        .document(role.name());

                ApiFuture<WriteResult> future = roleRef.set(roleData);

                return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                        .doOnSuccess(result ->
                                logger.info("✅ Persisted role {} to Firestore for user {}",
                                        role.name(), userId))
                        .then();

            } catch (Exception e) {
                logger.error("❌ Error assigning role {} to user {}: {}",
                        role, userId, e.getMessage(), e);
                return Mono.error(e);
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       Permission Checking
       ========================= */

    /**
     * Check if user has a specific permission.
     * Supports wildcard permissions (e.g., "users:*" implies "users:read").
     */
    public Mono<Boolean> hasPermission(String userId, String requiredPermission) {
        return Mono.justOrEmpty(userPermissions.get(userId))
                .flatMapMany(Flux::fromIterable)
                .any(perm -> perm.implies(
                        Permissions.fromNameSafe(requiredPermission).orElse(null)
                ))
                .switchIfEmpty(checkRolePermissionsFromFirestore(userId, requiredPermission))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Fallback to Firestore if not in cache
     */
    private Mono<Boolean> checkRolePermissionsFromFirestore(String userId, String requiredPermission) {
        return Mono.fromCallable(() ->
                        firestore.collection("users")
                                .document(userId)
                                .get()
                                .get()
                )
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(doc -> {
                    @SuppressWarnings("unchecked")
                    List<String> roleNames = (List<String>) doc.get("roles");

                    if (roleNames == null || roleNames.isEmpty()) {
                        return Mono.just(Collections.<Roles>emptyList());
                    }

                    List<Roles> roles = roleNames.stream()
                            .map(name -> Roles.fromName(name).orElse(null))
                            .filter(Objects::nonNull)
                            .toList();

                    return Mono.just(roles);
                })
                .flatMapMany(Flux::fromIterable)
                .flatMap(role -> Flux.fromIterable(
                        rolePermissions.getOrDefault(role, Collections.emptySet())
                ))
                .any(perm -> perm.implies(
                        Permissions.fromNameSafe(requiredPermission).orElse(null)
                ));
    }

    /* =========================
       Effective Permissions Resolution
       ========================= */

    /**
     * Resolve effective permissions for a user.
     * Combines role-based and user-specific permissions.
     *
     * @param user the user entity
     * @return set of permission names
     */
    @Override
    @Cacheable(value = "effectivePermissions", key = "#user.id")
    public Set<String> resolveEffectivePermissions(User user) {
        Set<Permissions> effectivePermsEnum = new HashSet<>();

        // 1. Add user-specific permissions
        if (user.getAdditionalPermissions() != null) {
            user.getAdditionalPermissions().forEach(permName -> {
                Permissions.fromNameSafe(permName).ifPresent(effectivePermsEnum::add);
            });
        }

        // 2. Add role-based permissions
        if (user.getRoleNames() != null && !user.getRoleNames().isEmpty()) {
            for (String roleName : user.getRoleNames()) {
                Roles.fromName(roleName).ifPresentOrElse(
                        role -> {
                            Set<Permissions> rolePerms = getPermissionsForRole(role);
                            effectivePermsEnum.addAll(rolePerms);
                            logger.debug("Added {} permissions from role {} for user {}",
                                    rolePerms.size(), role, user.getId());
                        },
                        () -> logger.warn("⚠️ Unknown role [{}] for user [{}]", roleName, user.getId())
                );
            }
        } else {
            logger.warn("⚠️ No roles found for user {}", user.getEmail());
        }

        // Convert to String names
        Set<String> permissionNames = effectivePermsEnum.stream()
                .map(Permissions::name)
                .collect(Collectors.toSet());

        logger.info("✅ Resolved {} effective permissions for user {}: {}",
                permissionNames.size(), user.getEmail(), permissionNames);

        return permissionNames;
    }

    /**
     * Alias method for backward compatibility
     */
    @Override
    public Set<String> resolveEffectivePermission(User user) {
        return resolveEffectivePermissions(user);
    }

    /* =========================
       ABAC: Attribute-Based Access Control
       ========================= */

    /**
     * Check permission with attribute conditions
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
     * Verify user attributes match resource requirements
     */
    private Mono<Boolean> checkAttributes(String userId, Map<String, String> resourceAttributes) {
        return Mono.justOrEmpty(userAttributes.get(userId))
                .map(userAttrNamespaces ->
                        resourceAttributes.entrySet().stream().allMatch(entry -> {
                            String[] parts = entry.getKey().split(":");
                            if (parts.length != 2) return false;

                            String namespace = parts[0];
                            String key = parts[1];

                            return userAttrNamespaces.getOrDefault(namespace, Map.of())
                                    .getOrDefault(key, "")
                                    .equals(entry.getValue());
                        }))
                .defaultIfEmpty(false)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public void addUserAttribute(String userId, String namespace, String key, String value) {
        userAttributes
                .computeIfAbsent(userId, k -> new ConcurrentHashMap<>())
                .computeIfAbsent(namespace, k -> new ConcurrentHashMap<>())
                .put(key, value);

        logger.debug("Added user attribute: {} {}:{}={}", userId, namespace, key, value);
    }

    /* =========================
       User-Specific Permission Management
       ========================= */

    @Override
    @CacheEvict(value = "effectivePermissions", key = "#userId")
    public void addPermission(String userId, Permissions permission) {
        userPermissions.computeIfAbsent(userId, k -> new HashSet<>()).add(permission);
        logger.info("Permission {} granted to user {}", permission, userId);
    }

    @Override
    @CacheEvict(value = "effectivePermissions", key = "#userId")
    public void removePermission(String userId, Permissions permission) {
        userPermissions.computeIfPresent(userId, (k, v) -> {
            v.remove(permission);
            return v.isEmpty() ? null : v;
        });
        logger.info("Permission {} revoked from user {}", permission, userId);
    }

    /* =========================
       Permission Provider Interface
       ========================= */

    @Override
    public String[] getPermissions() {
        return Arrays.stream(Permissions.values())
                .map(Permissions::name)
                .toArray(String[]::new);
    }

    @Override
    public String[] getSubPermissions(String perm) {
        return Arrays.stream(Permissions.values())
                .filter(p -> p.name().startsWith(perm + "_"))
                .map(Permissions::name)
                .toArray(String[]::new);
    }

    @Override
    public Object getLoadedRoles() {
        return new HashMap<>(rolePermissions);
    }

    @Override
    @CacheEvict(value = {"rolePermissions", "effectivePermissions"}, allEntries = true)
    public void reloadPermissions() {
        rolePermissions.clear();

        // Load default role permissions
        rolePermissions.put(Roles.SUPER_ADMIN,
                new HashSet<>(Arrays.asList(Permissions.getSuperAdminPermissions())));
        rolePermissions.put(Roles.ADMIN,
                new HashSet<>(Set.of(Permissions.ADMIN)));
        rolePermissions.put(Roles.MANAGER,
                new HashSet<>(Arrays.asList(Permissions.getManagerPermissions())));
        rolePermissions.put(Roles.USER,
                new HashSet<>(Arrays.asList(Permissions.getUserPermissions())));

        // Apply YAML overrides
        if (permissionsConfig != null && permissionsConfig.getRoleOverrides() != null) {
            permissionsConfig.getRoleOverrides().forEach((role, perms) -> {
                rolePermissions.computeIfAbsent(role, r -> new HashSet<>()).addAll(perms);
            });
        }

        logger.info("✅ Permissions reloaded: {} roles configured", rolePermissions.size());
        rolePermissions.forEach((role, perms) ->
                logger.debug("  - {}: {} permissions", role, perms.size())
        );
    }

    @Override
    public List<Permissions> deserializePermissions(List<String> permissions) {
        if (permissions == null || permissions.isEmpty()) {
            return Collections.emptyList();
        }

        return permissions.stream()
                .map(permission -> {
                    try {
                        return Permissions.valueOf(permission.toUpperCase());
                    } catch (IllegalArgumentException e) {
                        logger.warn("⚠️ Invalid permission string: {}", permission);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }
}