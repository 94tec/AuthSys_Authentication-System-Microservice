package com.techStack.authSys.service;

import com.techStack.authSys.config.PermissionsConfig;
import com.techStack.authSys.models.Permissions;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.AuthRepository;
import com.techStack.authSys.repository.PermissionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import javax.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class PermissionService implements PermissionProvider {

    private static final Logger logger = LoggerFactory.getLogger(PermissionService.class);

    private final Map<String, Set<Permissions>> userPermissions = new ConcurrentHashMap<>();
    private final Map<Roles, Set<Permissions>> rolePermissions = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Map<String, String>>> userAttributes = new ConcurrentHashMap<>();

    private final AuthRepository authRepository;
    private final PermissionsConfig permissionsConfig;

    public PermissionService(AuthRepository authRepository, PermissionsConfig permissionsConfig) {
        this.authRepository = authRepository;
        this.permissionsConfig = permissionsConfig;
    }

    @PostConstruct
    public void init() {
        reloadPermissions();
    }

    // --- Role-based permissions ---
    @Override
    public Set<Permissions> getPermissionsForRole(Roles role) {
        return rolePermissions.getOrDefault(role, Collections.emptySet());
    }

    @Cacheable(value = "rolePermissions", key = "#role.name()")
    public Set<Permissions> getRolePermissions(Roles role) {
        return rolePermissions.getOrDefault(role, Collections.emptySet());
    }
    @Override
    public Mono<Void> assignRole(String userId, Roles role) {
        return Mono.fromRunnable(() -> {
            Set<Permissions> permissions = getPermissionsForRole(role);
            userPermissions.put(userId, new HashSet<>(permissions));
            logger.info(STR."Role \{role} assigned to user \{userId}");
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    // --- Permission checking ---
    public Mono<Boolean> hasAccess(String userId, String path, String method) {
        return hasPermission(userId, method + ":" + path);
    }

    public Mono<Boolean> hasPermission(String userId, String requiredPermission) {
        return Mono.justOrEmpty(userPermissions.get(userId))
                .flatMapMany(Flux::fromIterable)
                .any(perm -> perm.implies(Permissions.fromNameSafe(requiredPermission).orElse(null)))
                .switchIfEmpty(checkRolePermissions(userId, requiredPermission))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Boolean> checkRolePermissions(String userId, String requiredPermission) {
        return authRepository.findById(userId)
                .map(User::getRoles)
                .flatMap(role -> Mono.justOrEmpty(rolePermissions.get(role)))
                .flatMapMany(Flux::fromIterable)
                .any(perm -> perm.implies(Permissions.fromNameSafe(requiredPermission).orElse(null)))
                .subscribeOn(Schedulers.boundedElastic());
    }

    // --- ABAC: Attribute-based access control ---
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
        logger.info(STR."User attribute added: \{userId}, \{namespace}:\{key}=\{value}");
    }

    // --- User-specific permission management ---
    @Override
    public void addPermission(String userId, Permissions permission) {
        userPermissions.computeIfAbsent(userId, k -> new HashSet<>()).add(permission);
        logger.info(STR."Permission \{permission} granted to user \{userId}");
    }
    @Override
    public void removePermission(String userId, Permissions permission) {
        userPermissions.computeIfPresent(userId, (k, v) -> {
            v.remove(permission);
            return v.isEmpty() ? null : v;
        });
        logger.info(STR."Permission \{permission} revoked from user \{userId}");
    }

    // --- PermissionProvider interface methods ---
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
        return rolePermissions;
    }

    @Override
    public void reloadPermissions() {
        rolePermissions.clear();

        // Default role permissions
        rolePermissions.put(Roles.SUPER_ADMIN, new HashSet<>(List.of(Permissions.getSuperAdminPermissions())));
        rolePermissions.put(Roles.ADMIN, new HashSet<>(List.of(Permissions.ADMIN)));
        rolePermissions.put(Roles.MANAGER, new HashSet<>(List.of(Permissions.MANAGER)));
        //rolePermissions.put(Roles.USER, new HashSet<>(List.of(Permissions.USER)));
        rolePermissions.put(Roles.USER, EnumSet.copyOf(List.of(Permissions.getUserPermissions())));


        addSpecialPermissions(Roles.MANAGER, Permissions.getManagerPermissions());
        addSpecialPermissions(Roles.USER, Permissions.getUserPermissions());

        // Apply YAML overrides from PermissionsConfig
        permissionsConfig.getRoleOverrides().forEach((role, perms) -> {
            rolePermissions.computeIfAbsent(role, r -> new HashSet<>()).addAll(perms);
        });
        logger.info("Permissions reloaded from config");
    }

    private void addSpecialPermissions(Roles role, Permissions[] permissions) {
        rolePermissions.computeIfAbsent(role, r -> new HashSet<>())
                .addAll(Arrays.asList(permissions));
    }

    // USAGE - Processing a full user object (from DB/session)
    //Need to avoid duplicates (e.g., for JWT claims)
    @Override
    public Set<String> resolveEffectivePermission(User user) {
        Set<String> effectivePermissions = new HashSet<>();

        for (String roleName : user.getRoleNames()) {
            Roles.fromName(roleName).ifPresent(role -> {
                Set<Permissions> rolePerms = getPermissionsForRole(role);
                rolePerms.forEach(p -> effectivePermissions.add(p.name())); // ✅ use .name()
            });
        }

        return effectivePermissions;
    }
    // USAGE - Processing roles from an incoming request
    // Need ordered output (e.g., UI menu)
    @Override
    public Set<String> resolveEffectivePermissions(User user) {
        Set<String> effectivePermissions = new HashSet<>();

        // 1. Add user-specific permissions
        if (user.getPermissions() != null && !user.getPermissions().isEmpty()) {
            effectivePermissions.addAll(user.getPermissions()); // assumed to be Strings like "STOCK_READ"
        }

        // 2. Add role-based permissions
        if (user.getRoleNames() != null && !user.getRoleNames().isEmpty()) {
            for (String roleName : user.getRoleNames()) {
                Roles.fromName(roleName).ifPresentOrElse(role -> {
                    Set<Permissions> rolePerms = getPermissionsForRole(role);
                    rolePerms.forEach(perm -> effectivePermissions.add(perm.name())); // ✅ only add enum name
                }, () -> logger.warn("⚠️ Unknown role [{}] for user [{}]", roleName, user.getId()));
            }
        }

        return effectivePermissions;
    }

    @Override
    public List<Permissions> deserializePermissions(List<String> permissions) {
        // Check if the list is not empty and process it
        if (permissions != null && !permissions.isEmpty()) {
            return permissions.stream()
                    .map(permission -> {
                        try {
                            return Permissions.valueOf(permission.toUpperCase()); // Convert string to Permission enum
                        } catch (IllegalArgumentException e) {
                            throw new IllegalArgumentException("Invalid permission string: " + permission, e);
                        }
                    })
                    .collect(Collectors.toList());
        } else {
            throw new IllegalArgumentException("Permissions list is empty or null");
        }
    }

    public String serializePermissions(List<Permissions> permissions) {
        return permissions.stream()
                .map(Permissions::name)
                .collect(Collectors.joining(","));
    }

}
