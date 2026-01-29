package com.techStack.authSys.service.authorization;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.*;
import com.techStack.authSys.config.security.PermissionsConfig;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import javax.annotation.PostConstruct;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class PermissionService implements PermissionProvider {

    private static final Logger logger = LoggerFactory.getLogger(PermissionService.class);

    private final Map<String, Set<Permissions>> userPermissions = new ConcurrentHashMap<>();
    private final Map<Roles, Set<Permissions>> rolePermissions = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Map<String, String>>> userAttributes = new ConcurrentHashMap<>();

    private final PermissionsConfig permissionsConfig;
    private final Firestore firestore;

    public PermissionService(PermissionsConfig permissionsConfig, Firestore firestore) {
        this.permissionsConfig = permissionsConfig;
        this.firestore = firestore;
    }

    @PostConstruct
    public void init() {
        reloadPermissions();
    }

    // ==================== ROLE-BASED PERMISSIONS ====================

    @Override
    @Cacheable(value = "rolePermissions", key = "#role.name()")
    public Set<Permissions> getPermissionsForRole(Roles role) {
        return rolePermissions.getOrDefault(role, Collections.emptySet());
    }

    @Override
    @CacheEvict(value = {"rolePermissions", "effectivePermissions"}, allEntries = true)
    public Mono<Void> assignRole(String userId, Roles role) {
        return Mono.defer(() -> {
            try {
                Set<Permissions> permissions = getPermissionsForRole(role);

                // Store in memory cache
                userPermissions.put(userId, new HashSet<>(permissions));

                logger.info("✅ Role {} assigned to user {} with {} permissions",
                        role, userId, permissions.size());

                // Persist to Firestore
                Map<String, Object> roleData = new HashMap<>();
                roleData.put("userId", userId);
                roleData.put("role", role.name());
                roleData.put("permissions", permissions.stream()
                        .map(Permissions::name)
                        .collect(Collectors.toList()));
                roleData.put("assignedAt", Instant.now());

                DocumentReference roleRef = firestore
                        .collection("users")
                        .document(userId)
                        .collection("user_roles")
                        .document(role.name());

                ApiFuture<WriteResult> future = roleRef.set(roleData);

                return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                        .doOnSuccess(result ->
                                logger.info("✅ Saved role {} to Firestore for user {}", role.name(), userId))
                        .then();

            } catch (Exception e) {
                logger.error("❌ Error assigning role {} to user {}: {}", role, userId, e.getMessage(), e);
                return Mono.error(e);
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ==================== PERMISSION CHECKING ====================

    public Mono<Boolean> hasPermission(String userId, String requiredPermission) {
        return Mono.justOrEmpty(userPermissions.get(userId))
                .flatMapMany(Flux::fromIterable)
                .any(perm -> perm.implies(Permissions.fromNameSafe(requiredPermission).orElse(null)))
                .switchIfEmpty(checkRolePermissionsFromFirestore(userId, requiredPermission))
                .subscribeOn(Schedulers.boundedElastic());
    }

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
                    List<String> roleNames = (List<String>) doc.get("roleNames");

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
                .any(perm ->
                        perm.implies(
                                Permissions.fromNameSafe(requiredPermission).orElse(null)
                        )
                );
    }

    // ==================== EFFECTIVE PERMISSIONS RESOLUTION ====================

    /**
     * ✅ FIXED: Resolves effective permissions as Permissions enum set
     * This is the CORRECT implementation for permission resolution
     */
    @Override
    @Cacheable(value = "effectivePermissions", key = "#user.id")
    public Set<String> resolveEffectivePermission(User user) {
        Set<Permissions> effectivePermsEnum = new HashSet<>();

        // 1. Add user-specific permissions (convert Strings to Enums)
        if (user.getPermissions() != null && !user.getPermissions().isEmpty()) {
            user.getPermissions().forEach(permName -> {
                Permissions.fromNameSafe(permName).ifPresent(effectivePermsEnum::add);
            });
        }

        // 2. Add role-based permissions
        if (user.getRoleNames() != null && !user.getRoleNames().isEmpty()) {
            for (String roleName : user.getRoleNames()) {
                Roles.fromName(roleName).ifPresentOrElse(role -> {
                    Set<Permissions> rolePerms = getPermissionsForRole(role);
                    effectivePermsEnum.addAll(rolePerms);
                }, () -> logger.warn("⚠️ Unknown role [{}] for user [{}]", roleName, user.getId()));
            }
        }

        if (user.getRoleNames() == null || user.getRoleNames().isEmpty()) {
            logger.warn("⚠️ No roles found for user {}", user.getEmail());
        }

        // Convert back to String names for storage/transmission
        Set<String> permissionNames = effectivePermsEnum.stream()
                .map(Permissions::name)
                .collect(Collectors.toSet());

        logger.info("✅ Resolved {} effective permissions for user {}: {}",
                permissionNames.size(), user.getEmail(), permissionNames);

        return permissionNames;
    }

    /**
     * ✅ Alias method - delegates to resolveEffectivePermission
     */
    @Override
    public Set<String> resolveEffectivePermissions(User user) {
        return resolveEffectivePermission(user);
    }

    // ==================== ABAC: ATTRIBUTE-BASED ACCESS CONTROL ====================

    public Mono<Boolean> hasPermissionWithAttributes(String userId, String requiredPermission, Map<String, String> resourceAttributes) {
        return Mono.zip(
                hasPermission(userId, requiredPermission),
                checkAttributes(userId, resourceAttributes)
        ).map(tuple -> tuple.getT1() && tuple.getT2());
    }

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
        logger.info("User attribute added: {}, {}:{}={}", userId, namespace, key, value);
    }

    // ==================== USER-SPECIFIC PERMISSION MANAGEMENT ====================

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

    // ==================== PERMISSION PROVIDER INTERFACE ====================

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

        // Default role permissions
        rolePermissions.put(Roles.SUPER_ADMIN, new HashSet<>(Arrays.asList(Permissions.getSuperAdminPermissions())));
        rolePermissions.put(Roles.ADMIN, new HashSet<>(Set.of(Permissions.ADMIN)));
        rolePermissions.put(Roles.MANAGER, new HashSet<>(Set.of(Permissions.MANAGER)));
        rolePermissions.put(Roles.USER, new HashSet<>(Arrays.asList(Permissions.getUserPermissions())));

        addSpecialPermissions(Roles.MANAGER, Permissions.getManagerPermissions());
        addSpecialPermissions(Roles.USER, Permissions.getUserPermissions());

        // Apply YAML overrides
        permissionsConfig.getRoleOverrides().forEach((role, perms) -> {
            rolePermissions.computeIfAbsent(role, r -> new HashSet<>()).addAll(perms);
        });

        logger.info("✅ Permissions reloaded: {} roles configured", rolePermissions.size());
    }

    private void addSpecialPermissions(Roles role, Permissions[] permissions) {
        rolePermissions.computeIfAbsent(role, r -> new HashSet<>())
                .addAll(Arrays.asList(permissions));
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