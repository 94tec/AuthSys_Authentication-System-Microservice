package com.techStack.authSys.models.firestore;

import com.google.cloud.firestore.annotation.DocumentId;
import com.google.cloud.firestore.annotation.PropertyName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

/**
 * Firestore document: roles/{roleId}
 *
 * roleId is the role name in lowercase: "admin", "designer", "manager"
 *
 * Example document:
 * {
 *   "name":         "ADMIN",
 *   "level":        90,
 *   "description":  "Administrative access",
 *   "isSystemRole": true,
 *   "createdAt":    <timestamp>
 * }
 *
 * isSystemRole / @PropertyName note:
 *   Lombok @Data generates isSystemRole() as the getter for a boolean field
 *   named "systemRole", which confuses Firestore's deserializer — it looks for
 *   a field named "systemRole" in the document, not "isSystemRole".
 *
 *   Fix: rename the field to "isSystemRole" so Lombok generates isIsSystemRole()
 *   (ugly), OR keep the field named "systemRole" but explicitly annotate both
 *   getter and setter with @PropertyName("isSystemRole") so Firestore maps
 *   to/from the correct document key regardless of what Lombok names the accessor.
 *
 *   We use the explicit @PropertyName approach on a non-boolean field name
 *   "systemRole" to keep Lombok's generated accessors clean (isSystemRole() clash
 *   avoided), while the Firestore document key stays "isSystemRole" for
 *   backward compatibility with any existing documents.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FirestoreRole {

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------

    /** Firestore document ID — same as name.toLowerCase(). e.g. "admin" */
    @DocumentId
    private String id;

    /** Role name in UPPER_SNAKE_CASE. e.g. "ADMIN" */
    private String name;

    /**
     * Numeric privilege level.
     * Higher = more privileged. Used for hierarchy comparisons.
     * e.g. SUPER_ADMIN=100, ADMIN=90, MANAGER=70, USER=10, GUEST=1
     */
    private int level;

    /** Human-readable description shown in admin UIs. */
    private String description;

    /**
     * Whether this role is a system role that cannot be deleted via API.
     *
     * Field is named "systemRole" to keep Lombok's generated accessor clean.
     * @PropertyName("isSystemRole") ensures Firestore reads/writes the document
     * key "isSystemRole", preserving compatibility with existing documents.
     *
     * Lombok generates:
     *   getter → isSystemRole()   (boolean convention)
     *   setter → setSystemRole()
     *
     * Without @PropertyName, Firestore's deserializer would look for a document
     * field named "systemRole" (from the setter name), not "isSystemRole".
     * The annotation overrides that mapping explicitly.
     */
    @PropertyName("isSystemRole")
    private boolean systemRole;

    /** When this role document was first created. */
    private Instant createdAt;

    // -------------------------------------------------------------------------
    // Explicit accessors for the boolean field
    //
    // We override Lombok's generated getter/setter here ONLY to attach
    // @PropertyName so Firestore's reflection-based mapper picks up the
    // correct document key on both read and write.
    // -------------------------------------------------------------------------

    @PropertyName("isSystemRole")
    public boolean isSystemRole() {
        return systemRole;
    }

    @PropertyName("isSystemRole")
    public void setSystemRole(boolean systemRole) {
        this.systemRole = systemRole;
    }

    // -------------------------------------------------------------------------
    // Factory / derivation helpers
    // -------------------------------------------------------------------------

    /**
     * Derives the Firestore document ID from a role name.
     * "ADMIN" → "admin"
     *
     * @param roleName uppercase role name
     * @return lowercase document ID
     */
    public static String toDocumentId(String roleName) {
        if (roleName == null || roleName.isBlank()) {
            throw new IllegalArgumentException("Role name must not be null or blank");
        }
        return roleName.toLowerCase();
    }

    /**
     * Derives the role name from a Firestore document ID.
     * "admin" → "ADMIN"
     *
     * @param documentId lowercase document ID
     * @return uppercase role name
     */
    public static String fromDocumentId(String documentId) {
        if (documentId == null || documentId.isBlank()) {
            throw new IllegalArgumentException("Document ID must not be null or blank");
        }
        return documentId.toUpperCase();
    }

    /**
     * Safe parse from a role name string.
     * Returns empty Optional instead of throwing on null/blank input.
     *
     * Used when reading role names from Firestore documents where the
     * value may be missing or stale, consistent with Roles.fromName()
     * and PermissionEffect.fromStringSafe() patterns in this codebase.
     *
     * @param name role name string (case-insensitive)
     * @return Optional containing the document ID, empty if name is null or blank
     */
    public static Optional<String> toDocumentIdSafe(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(name.toLowerCase());
    }

    /**
     * Creates a new system role (cannot be deleted via API).
     *
     * @param name        uppercase role name e.g. "ADMIN"
     * @param level       privilege level
     * @param description human-readable description
     * @param createdAt   creation timestamp
     * @return fully populated FirestoreRole
     */
    public static FirestoreRole systemRole(
            String name,
            int level,
            String description,
            Instant createdAt
    ) {
        return FirestoreRole.builder()
                .id(toDocumentId(name))
                .name(name)
                .level(level)
                .description(description)
                .systemRole(true)
                .createdAt(createdAt)
                .build();
    }

    /**
     * Creates a new custom role (can be deleted via API).
     *
     * @param name        uppercase role name e.g. "CONTRACTOR"
     * @param level       privilege level
     * @param description human-readable description
     * @param createdAt   creation timestamp
     * @return fully populated FirestoreRole
     */
    public static FirestoreRole customRole(
            String name,
            int level,
            String description,
            Instant createdAt
    ) {
        return FirestoreRole.builder()
                .id(toDocumentId(name))
                .name(name)
                .level(level)
                .description(description)
                .systemRole(false)
                .createdAt(createdAt)
                .build();
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /**
     * Whether this role has a higher privilege level than the given level.
     *
     * @param otherLevel the level to compare against
     * @return true if this role's level is strictly greater
     */
    public boolean hasHigherLevelThan(int otherLevel) {
        return this.level > otherLevel;
    }

    /**
     * Whether this role has equal or higher privilege than the given level.
     *
     * @param otherLevel the level to compare against
     * @return true if this role's level is greater than or equal
     */
    public boolean hasAtLeastLevel(int otherLevel) {
        return this.level >= otherLevel;
    }

    @Override
    public String toString() {
        return String.format("FirestoreRole[id=%s, name=%s, level=%d, systemRole=%b]",
                id, name, level, systemRole);
    }
}