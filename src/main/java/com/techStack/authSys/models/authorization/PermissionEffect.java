package com.techStack.authSys.models.authorization;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Optional;

/**
 * Represents whether a direct user permission override is a grant or a denial.
 *
 * GRANT  → explicitly give this user a permission their role doesn't have
 * DENY   → explicitly strip a permission their role normally grants
 *
 * Denials always win over grants. If a user's role grants "portfolio:publish"
 * but a DENY override exists, the permission is not included in their token.
 *
 * Serialization:
 *   - @JsonValue  → serializes as "GRANT" / "DENY"
 *   - @JsonCreator on fromString() → deserializes from those strings
 *
 * Firestore stores these as plain strings; use fromStringSafe() when
 * reading from Firestore to avoid crashing on stale/corrupt data.
 */
public enum PermissionEffect {

    GRANT("GRANT"),
    DENY("DENY");

    private final String value;

    PermissionEffect(String value) {
        this.value = value;
    }

    // -------------------------------------------------------------------------
    // Serialization
    // -------------------------------------------------------------------------

    @JsonValue
    public String getValue() {
        return value;
    }

    // -------------------------------------------------------------------------
    // Parsing — strict (throws on unknown input, used for trusted sources)
    // -------------------------------------------------------------------------

    /**
     * Parse from string, throwing on unrecognized values.
     *
     * Use this when the input comes from a trusted internal source
     * (e.g., a validated API request body) and a bad value is a
     * programming error that should fail loudly.
     *
     * @param value "GRANT" or "DENY" (case-insensitive)
     * @throws IllegalArgumentException if value is null, blank, or unrecognized
     */
    @JsonCreator
    public static PermissionEffect fromString(String value) {
        return fromStringSafe(value)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unknown PermissionEffect: '" + value + "'. Must be GRANT or DENY."));
    }

    // -------------------------------------------------------------------------
    // Parsing — safe (returns Optional, used when reading from Firestore/DB)
    // -------------------------------------------------------------------------

    /**
     * Parse from string, returning empty Optional on unrecognized values.
     *
     * Use this when the input comes from Firestore or any external/persisted
     * source where stale or corrupt data is possible. The caller decides
     * how to handle an absent result rather than catching a runtime exception.
     *
     * Example:
     *   PermissionEffect.fromStringSafe(doc.getString("effect"))
     *       .ifPresentOrElse(this::applyEffect,
     *           () -> log.warn("Unknown effect for doc {}", docId));
     *
     * @param value raw string from storage
     * @return Optional containing the matched enum, or empty if null/blank/unknown
     */
    public static Optional<PermissionEffect> fromStringSafe(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return switch (value.toUpperCase().trim()) {
            case "GRANT" -> Optional.of(GRANT);
            case "DENY"  -> Optional.of(DENY);
            default      -> Optional.empty();
        };
    }

    // -------------------------------------------------------------------------
    // Predicates
    // -------------------------------------------------------------------------

    public boolean isGrant() { return this == GRANT; }
    public boolean isDeny()  { return this == DENY;  }

    // -------------------------------------------------------------------------
    // String representation
    // -------------------------------------------------------------------------

    @Override
    public String toString() {
        return value;
    }
}