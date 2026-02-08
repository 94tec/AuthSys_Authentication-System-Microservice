package com.techStack.authSys.repository.authorization;

import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;

/**
 * Permission Provider Interface
 *
 * Defines contract for permission management across the system.
 * Implemented by PermissionService.
 */
public interface PermissionProvider {

    /* =========================
       Role-Based Permissions
       ========================= */

    /**
     * Get all permissions for a given role
     */
    Set<Permissions> getPermissionsForRole(Roles role);

    /**
     * Assign a role to a user
     */
    Mono<Void> assignRole(String userId, Roles role);

    /**
     * Reload permissions from configuration
     */
    void reloadPermissions();

    /* =========================
       User-Specific Permissions
       ========================= */

    /**
     * Add a specific permission to a user
     */
    void addPermission(String userId, Permissions permission);

    /**
     * Remove a specific permission from a user
     */
    void removePermission(String userId, Permissions permission);

    /* =========================
       Effective Permission Resolution
       ========================= */

    /**
     * Resolve effective permissions for a user.
     * Combines role-based and user-specific permissions.
     *
     * @param user the user entity
     * @return set of permission names (Strings)
     */
    Set<String> resolveEffectivePermissions(User user);

    /* =========================
       ABAC: Attribute-Based Access Control
       ========================= */

    Set<String> resolveEffectivePermission(User user);

    /**
     * Add an attribute to a user for ABAC evaluation
     */
    void addUserAttribute(String userId, String namespace, String key, String value);

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Get all available permissions in the system
     */
    String[] getPermissions();

    /**
     * Get sub-permissions for a given permission prefix
     */
    String[] getSubPermissions(String permissionPrefix);

    /**
     * Get all loaded role configurations
     */
    Object getLoadedRoles();

    /**
     * Deserialize permission strings to Permission enums
     */
    List<Permissions> deserializePermissions(List<String> permissionNames);
}