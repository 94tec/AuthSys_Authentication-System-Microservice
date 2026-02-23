package com.techStack.authSys.repository.authorization;

import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;

/**
 * Permission Provider Interface
 *
 * Defines the contract for permission management across the system.
 * Implemented by PermissionService.
 *
 * Migration note — v1 → v2:
 *   All methods previously referencing the Permissions enum have been
 *   updated to use String-based permission full names (e.g. "portfolio:publish").
 *
 *   Removed:
 *     Set<Permissions> getPermissionsForRole(Roles)         → Set<String>
 *     void addPermission(String, Permissions)               → void addPermission(String, String)
 *     void removePermission(String, Permissions)            → void removePermission(String, String)
 *     List<Permissions> deserializePermissions(List<String>) → List<String>
 *
 *   The Permissions enum is no longer referenced anywhere in this interface.
 *   Role-based permissions are now resolved from Firestore (role_permissions/
 *   collection seeded by PermissionSeeder) rather than from an in-memory enum map.
 */
public interface PermissionProvider {

    // -------------------------------------------------------------------------
    // Role-based permissions
    // -------------------------------------------------------------------------

    /**
     * Returns all permission full names for a given role.
     *
     * Reads from role_permissions/{roleName} in Firestore (seeded by PermissionSeeder).
     * Result format: {"portfolio:view", "portfolio:create", "user:read", ...}
     *
     * @param role the role enum value
     * @return set of permission full name strings, never null
     */
    Set<String> getPermissionsForRole(Roles role);

    /**
     * Assigns a role to a user, persisting the change to FirestoreUserPermissions.
     *
     * @param userId the user's Firebase UID
     * @param role   the role to assign
     * @return Mono completing when the Firestore write is acknowledged
     */
    Mono<Void> assignRole(String userId, Roles role);

    /**
     * Evicts all permission caches and clears in-memory ABAC state.
     * Call after PermissionSeeder re-seeds Firestore following a YAML change.
     */
    void reloadPermissions();

    // -------------------------------------------------------------------------
    // User-specific permission management
    // -------------------------------------------------------------------------

    /**
     * Explicitly grants a permission to a user beyond their role defaults.
     *
     * Persists a grant entry to FirestoreUserPermissions.
     * If the permission was previously denied, the denial is removed first.
     *
     * @param userId     the user's Firebase UID
     * @param permission full permission name e.g. "portfolio:publish"
     */
    void addPermission(String userId, String permission);

    /**
     * Explicitly denies a permission for a user, stripping it even if
     * their role normally grants it.
     *
     * Persists a denial entry to FirestoreUserPermissions.
     * Denials always win over grants at JWT resolution time.
     * If the permission was previously granted, the grant is removed first.
     *
     * @param userId     the user's Firebase UID
     * @param permission full permission name e.g. "system:backup"
     */
    void removePermission(String userId, String permission);

    // -------------------------------------------------------------------------
    // Effective permission resolution
    // -------------------------------------------------------------------------

    /**
     * Resolves the complete set of effective permission strings for a user.
     *
     * Combines:
     *   1. Role-based permissions from FirestoreRolePermissionsRepository
     *   2. User-specific additionalPermissions from the User entity
     *
     * Note: Explicit grants and denials from FirestoreUserPermissions are
     * applied by AuthService at JWT generation time, not here.
     *
     * @param user the user entity with roleNames and additionalPermissions populated
     * @return unmodifiable set of effective permission full name strings
     */
    Set<String> resolveEffectivePermissions(User user);

    /**
     * Alias for resolveEffectivePermissions — retained for backward compatibility.
     *
     * @param user the user entity
     * @return set of effective permission full name strings
     */
    Set<String> resolveEffectivePermission(User user);

    // -------------------------------------------------------------------------
    // ABAC: Attribute-Based Access Control
    // -------------------------------------------------------------------------

    /**
     * Stores a user attribute for ABAC policy evaluation.
     *
     * Attributes are ephemeral (in-memory only, not persisted to Firestore).
     * Set at login/registration time, lost on application restart.
     *
     * @param userId    the user's Firebase UID
     * @param namespace attribute namespace e.g. "department", "access", "approval"
     * @param key       attribute key     e.g. "name",       "level",  "can_approve"
     * @param value     attribute value   e.g. "engineering", "admin", "manager,user"
     */
    void addUserAttribute(String userId, String namespace, String key, String value);

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /**
     * Returns all permission full names known to the system.
     * Reads from the union of all role_permissions documents.
     *
     * @return array of permission full name strings
     */
    String[] getPermissions();

    /**
     * Returns all permission full names within a given namespace.
     *
     * e.g. getSubPermissions("portfolio")
     *        → ["portfolio:view", "portfolio:create", "portfolio:publish", ...]
     *
     * @param namespace the namespace prefix (without colon)
     * @return array of matching permission full name strings
     */
    String[] getSubPermissions(String namespace);

    /**
     * Returns the loaded role → permissions mapping for diagnostics.
     * Used by admin endpoints to inspect the current permission state.
     *
     * @return Map<String, List<String>> of roleName → permission list,
     *         returned as Object to avoid coupling callers to the map type
     */
    Object getLoadedRoles();

    /**
     * Filters and validates a list of permission strings.
     *
     * Removes null/blank entries and logs warnings for malformed strings
     * (those without a ':' separator). Returns the cleaned list.
     *
     * @param permissions raw list of permission strings from storage or API input
     * @return unmodifiable list of valid permission full name strings
     */
    List<String> deserializePermissions(List<String> permissions);
}