package com.techStack.authSys.models.firestore;

import com.google.cloud.firestore.annotation.DocumentId;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Firestore document: permissions/{permissionId}
 *
 * One document per permission. The document ID uses double-underscore as a
 * delimiter between namespace and action:
 *
 *   "portfolio:bulk_export"  →  "portfolio__bulk_export"
 *
 * Why double-underscore?
 *   Single underscore is ambiguous — "portfolio_bulk_export" could mean
 *   namespace="portfolio", action="bulk_export"
 *   OR namespace="portfolio_bulk", action="export".
 *   Double-underscore cannot appear in valid namespace or action names,
 *   so splitting on "__" always produces exactly two parts.
 *
 * Convention: namespace and action names use single underscores only
 * (snake_case). Double-underscore is reserved as this delimiter.
 *
 * Example Firestore document (id: "portfolio__publish"):
 * {
 *   "namespace":   "portfolio",
 *   "action":      "publish",
 *   "fullName":    "portfolio:publish",
 *   "description": "Publish collections publicly",
 *   "category":    "PORTFOLIO"
 * }
 *
 * The fullName field ("portfolio:publish") is the authoritative string
 * that goes into JWTs, role_permissions documents, and user grants/denials.
 * Always use fullName as the source of truth — never reconstruct it from
 * the document ID.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FirestorePermission {

    /** Separator used in Firestore document IDs. Cannot appear in namespace/action names. */
    private static final String DOC_ID_SEPARATOR = "__";

    /** Separator used in permission full names (JWTs, Firestore lists). */
    private static final String FULL_NAME_SEPARATOR = ":";

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------

    @DocumentId
    private String id;          // "portfolio__publish"

    private String namespace;   // "portfolio"
    private String action;      // "publish"
    private String fullName;    // "portfolio:publish"  ← what goes in JWT / grants / denials
    private String description; // "Publish collections publicly"
    private String category;    // "PORTFOLIO"

    // -------------------------------------------------------------------------
    // Document ID helpers
    // -------------------------------------------------------------------------

    /**
     * Derives the Firestore document ID from a permission full name.
     *
     *   "portfolio:publish"     → "portfolio__publish"
     *   "portfolio:bulk_export" → "portfolio__bulk_export"
     *
     * @param fullName the colon-separated permission name
     * @return the double-underscore-separated document ID
     * @throws IllegalArgumentException if fullName is null, blank, or has no colon
     */
    public static String toDocumentId(String fullName) {
        validateFullName(fullName);
        return fullName.replace(FULL_NAME_SEPARATOR, DOC_ID_SEPARATOR);
    }

    /**
     * Reconstructs the full name from a Firestore document ID.
     *
     *   "portfolio__publish"     → "portfolio:publish"
     *   "portfolio__bulk_export" → "portfolio:bulk_export"
     *
     * This is the inverse of toDocumentId(). Use when iterating
     * the permissions collection and you need the JWT-safe full name.
     *
     * @param documentId the double-underscore-separated document ID
     * @return the colon-separated full name
     * @throws IllegalArgumentException if documentId is null, blank, or has no double-underscore
     */
    public static String fromDocumentId(String documentId) {
        if (documentId == null || documentId.isBlank()) {
            throw new IllegalArgumentException(
                    "FirestorePermission documentId must not be null or blank");
        }
        if (!documentId.contains(DOC_ID_SEPARATOR)) {
            throw new IllegalArgumentException(
                    "FirestorePermission documentId '" + documentId +
                            "' does not contain the expected separator '__'. " +
                            "Was this document created with the old single-underscore scheme?");
        }
        // Replace only the FIRST occurrence so action names with underscores are preserved
        return documentId.replaceFirst(DOC_ID_SEPARATOR, FULL_NAME_SEPARATOR);
    }

    // -------------------------------------------------------------------------
    // Full name helpers
    // -------------------------------------------------------------------------

    /**
     * Derives the full name from separate namespace and action strings.
     *
     *   ("portfolio", "publish")     → "portfolio:publish"
     *   ("portfolio", "bulk_export") → "portfolio:bulk_export"
     *
     * @param namespace the permission namespace (e.g. "portfolio")
     * @param action    the permission action   (e.g. "publish")
     * @return the colon-separated full name
     */
    public static String toFullName(String namespace, String action) {
        if (namespace == null || namespace.isBlank()) {
            throw new IllegalArgumentException("Permission namespace must not be null or blank");
        }
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("Permission action must not be null or blank");
        }
        return namespace + FULL_NAME_SEPARATOR + action;
    }

    /**
     * Splits a full name into a two-element array [namespace, action].
     *
     *   "portfolio:publish" → ["portfolio", "publish"]
     *
     * @param fullName the colon-separated permission name
     * @return String[2] where [0] is namespace and [1] is action
     * @throws IllegalArgumentException if fullName is null, blank, or has no colon
     */
    public static String[] splitFullName(String fullName) {
        validateFullName(fullName);
        String[] parts = fullName.split(FULL_NAME_SEPARATOR, 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException(
                    "Permission fullName '" + fullName + "' must contain exactly one ':'");
        }
        return parts;
    }

    // -------------------------------------------------------------------------
    // Factory method
    // -------------------------------------------------------------------------

    /**
     * Constructs a FirestorePermission from its component parts,
     * deriving the document ID and full name automatically.
     *
     * @param namespace   e.g. "portfolio"
     * @param action      e.g. "bulk_export"
     * @param description human-readable description
     * @param category    grouping category e.g. "PORTFOLIO"
     * @return fully populated FirestorePermission ready for Firestore write
     */
    public static FirestorePermission of(
            String namespace,
            String action,
            String description,
            String category
    ) {
        String full = toFullName(namespace, action);
        return FirestorePermission.builder()
                .id(toDocumentId(full))
                .namespace(namespace)
                .action(action)
                .fullName(full)
                .description(description)
                .category(category)
                .build();
    }

    // -------------------------------------------------------------------------
    // Internal validation
    // -------------------------------------------------------------------------

    private static void validateFullName(String fullName) {
        if (fullName == null || fullName.isBlank()) {
            throw new IllegalArgumentException(
                    "Permission fullName must not be null or blank");
        }
        if (!fullName.contains(FULL_NAME_SEPARATOR)) {
            throw new IllegalArgumentException(
                    "Permission fullName '" + fullName + "' must contain ':'  " +
                            "(expected format: namespace:action)");
        }
    }
}