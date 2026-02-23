package com.techStack.authSys.models.firestore;

import com.google.cloud.firestore.annotation.DocumentId;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Firestore document: user_permissions/{firebaseUid}
 *
 * One document per user. This is the single Firestore read that builds the JWT.
 *
 * Effective permissions = role_permissions(roles) + grants - denials
 *
 * Example document:
 * {
 *   "roles":     ["ADMIN"],
 *   "grants":    ["portfolio:publish"],   ← extra permissions beyond role
 *   "denials":   ["system:backup"],       ← strip permissions the role grants
 *   "updatedAt": <timestamp>
 * }
 *
 * Mutation contract:
 *   - grant(p)       → adds to grants,  removes from denials  (grant wins over prior denial)
 *   - deny(p)        → adds to denials, removes from grants   (denial wins over prior grant)
 *   - clearOverride  → removes from both lists                (reverts to role default)
 *   - Denials always win at resolution time in AuthService.
 *
 * Null-safety:
 *   Firestore's deserializer may leave list fields null if the document
 *   was written before these fields existed (e.g. legacy documents that
 *   predate the grants/denials model). All mutation and read methods
 *   guard against null lists via ensureInitialized() before operating.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FirestoreUserPermissions {

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------

    /** Firebase Auth UID — Firestore document ID and cross-system key. */
    @DocumentId
    private String firebaseUid;

    /**
     * Role names this user holds. e.g. ["ADMIN"]
     * Most users have exactly one. Multiple roles are supported.
     * The role names here must match documents in the roles/ collection.
     */
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    /**
     * Explicit permission grants beyond what the role provides.
     * e.g. give a USER "portfolio:analytics" without making them a MANAGER.
     * Format: "namespace:action" strings matching the permissions/ collection.
     */
    @Builder.Default
    private List<String> grants = new ArrayList<>();

    /**
     * Explicit permission denials — strips a permission even if the role grants it.
     * e.g. deny a MANAGER "system:audit_log" for this specific user.
     * Denials always win over grants at JWT resolution time.
     * Format: "namespace:action" strings matching the permissions/ collection.
     */
    @Builder.Default
    private List<String> denials = new ArrayList<>();

    /** Last time this document was written. Set by the repository on every save. */
    private Instant updatedAt;

    // -------------------------------------------------------------------------
    // Role management
    // -------------------------------------------------------------------------

    /**
     * Adds a role to this user if not already present.
     *
     * @param roleName uppercase role name e.g. "MANAGER"
     */
    public void addRole(String roleName) {
        ensureRolesInitialized();
        if (!roles.contains(roleName)) {
            roles.add(roleName);
        }
    }

    /**
     * Removes a role from this user.
     * No-op if the role is not present.
     *
     * @param roleName uppercase role name e.g. "MANAGER"
     */
    public void removeRole(String roleName) {
        ensureRolesInitialized();
        roles.remove(roleName);
    }

    /**
     * Whether this user holds the given role.
     *
     * @param roleName uppercase role name
     * @return true if present in the roles list
     */
    public boolean hasRole(String roleName) {
        ensureRolesInitialized();
        return roles.contains(roleName);
    }

    // -------------------------------------------------------------------------
    // Permission override management
    // -------------------------------------------------------------------------

    /**
     * Explicitly grants a permission to this user beyond their role defaults.
     *
     * If the permission was previously denied, the denial is removed first —
     * a permission cannot be simultaneously granted and denied.
     *
     * @param permission full permission name e.g. "portfolio:publish"
     */
    public void grant(String permission) {
        ensureGrantsInitialized();
        ensureDenialsInitialized();
        denials.remove(permission);
        if (!grants.contains(permission)) {
            grants.add(permission);
        }
    }

    /**
     * Explicitly denies a permission for this user, stripping it even if
     * their role normally grants it.
     *
     * If the permission was previously granted, the grant is removed first —
     * a permission cannot be simultaneously granted and denied.
     * Denials always win at JWT resolution time.
     *
     * @param permission full permission name e.g. "system:backup"
     */
    public void deny(String permission) {
        ensureGrantsInitialized();
        ensureDenialsInitialized();
        grants.remove(permission);
        if (!denials.contains(permission)) {
            denials.add(permission);
        }
    }

    /**
     * Removes any explicit grant or denial override for this permission,
     * reverting the user to their role's default behaviour.
     *
     * @param permission full permission name e.g. "portfolio:publish"
     */
    public void clearOverride(String permission) {
        ensureGrantsInitialized();
        ensureDenialsInitialized();
        grants.remove(permission);
        denials.remove(permission);
    }

    /**
     * Removes all explicit grants and denials, reverting the user fully
     * to their role-based permissions.
     */
    public void clearAllOverrides() {
        ensureGrantsInitialized();
        ensureDenialsInitialized();
        grants.clear();
        denials.clear();
    }

    // -------------------------------------------------------------------------
    // Read helpers
    // -------------------------------------------------------------------------

    /**
     * Returns an unmodifiable view of the grants list.
     * Never null — returns empty list if the field was not present in Firestore.
     */
    public List<String> getGrants() {
        ensureGrantsInitialized();
        return Collections.unmodifiableList(grants);
    }

    /**
     * Returns an unmodifiable view of the denials list.
     * Never null — returns empty list if the field was not present in Firestore.
     */
    public List<String> getDenials() {
        ensureDenialsInitialized();
        return Collections.unmodifiableList(denials);
    }

    /**
     * Returns an unmodifiable view of the roles list.
     * Never null — returns empty list if the field was not present in Firestore.
     */
    public List<String> getRoles() {
        ensureRolesInitialized();
        return Collections.unmodifiableList(roles);
    }

    /**
     * Whether this user has any explicit overrides (grants or denials).
     */
    public boolean hasOverrides() {
        ensureGrantsInitialized();
        ensureDenialsInitialized();
        return !grants.isEmpty() || !denials.isEmpty();
    }

    /**
     * Whether a specific permission has been explicitly granted to this user
     * (independent of role permissions).
     */
    public boolean isExplicitlyGranted(String permission) {
        ensureGrantsInitialized();
        return grants.contains(permission);
    }

    /**
     * Whether a specific permission has been explicitly denied for this user.
     */
    public boolean isExplicitlyDenied(String permission) {
        ensureDenialsInitialized();
        return denials.contains(permission);
    }

    // -------------------------------------------------------------------------
    // Factory methods
    // -------------------------------------------------------------------------

    /**
     * Creates a default document for a brand new user using a provided Clock.
     * Everyone starts as USER with no overrides.
     *
     * Accepts Clock instead of calling Instant.now() directly so that
     * callers (and tests) can control the timestamp.
     *
     * @param firebaseUid the Firebase Auth UID
     * @param clock       clock to use for the updatedAt timestamp
     * @return default FirestoreUserPermissions with USER role, no overrides
     */
    public static FirestoreUserPermissions defaultFor(String firebaseUid, Clock clock) {
        return FirestoreUserPermissions.builder()
                .firebaseUid(firebaseUid)
                .roles(new ArrayList<>(List.of("USER")))
                .grants(new ArrayList<>())
                .denials(new ArrayList<>())
                .updatedAt(clock.instant())
                .build();
    }

    /**
     * Creates a default document for a brand new user with a specific role.
     *
     * @param firebaseUid the Firebase Auth UID
     * @param roleName    the initial role name e.g. "MANAGER"
     * @param clock       clock to use for the updatedAt timestamp
     * @return FirestoreUserPermissions with the given role, no overrides
     */
    public static FirestoreUserPermissions forRole(
            String firebaseUid,
            String roleName,
            Clock clock
    ) {
        return FirestoreUserPermissions.builder()
                .firebaseUid(firebaseUid)
                .roles(new ArrayList<>(List.of(roleName)))
                .grants(new ArrayList<>())
                .denials(new ArrayList<>())
                .updatedAt(clock.instant())
                .build();
    }

    // -------------------------------------------------------------------------
    // Null-safety initializers
    //
    // Firestore's deserializer skips missing fields, leaving them null.
    // These guards ensure list fields are always non-null before any
    // read or write operation, without requiring a @PostConstruct or
    // custom deserializer.
    // -------------------------------------------------------------------------

    private void ensureRolesInitialized() {
        if (roles == null) roles = new ArrayList<>();
    }

    private void ensureGrantsInitialized() {
        if (grants == null) grants = new ArrayList<>();
    }

    private void ensureDenialsInitialized() {
        if (denials == null) denials = new ArrayList<>();
    }

    // -------------------------------------------------------------------------
    // String representation
    // -------------------------------------------------------------------------

    @Override
    public String toString() {
        return String.format(
                "FirestoreUserPermissions[uid=%s, roles=%s, grants=%d, denials=%d, updatedAt=%s]",
                firebaseUid, roles, grants == null ? 0 : grants.size(),
                denials == null ? 0 : denials.size(), updatedAt);
    }
}