package com.techStack.authSys.repository.user;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.cloud.firestore.SetOptions;
import com.techStack.authSys.models.user.UserDocument;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

/**
 * Firestore repository for UserDocument.
 *
 * Collection: "users"
 * Document ID: Firebase Auth UID
 *
 * Persistence rules:
 *   - This repository owns all Firestore writes for the users/ collection.
 *   - UserEntity (JPA) handles PostgreSQL writes — never call both in the
 *     same transaction.
 *   - All blocking Firestore SDK calls are wrapped here so callers
 *     can offload to Schedulers.boundedElastic() at the service layer.
 *
 * Write strategy:
 *   - save()         → full document overwrite (use for creates + full updates)
 *   - updateFields() → partial merge (use for single-field updates like lastLogin)
 *   - softDelete()   → sets status=DEACTIVATED, never hard deletes
 */
@Repository
@RequiredArgsConstructor
@Slf4j
public class UserDocumentRepository {

    private final Firestore firestore;

    private static final String COLLECTION = "users";

    /* =========================
       READ — Single Document
       ========================= */

    /**
     * Find a user by their Firebase UID.
     * Firebase UID is the Firestore document ID.
     *
     * @param firebaseUid Firebase Auth UID
     * @return Optional containing the UserDocument if found
     */
    public Optional<UserDocument> findById(String firebaseUid) {
        if (firebaseUid == null || firebaseUid.isBlank()) {
            log.warn("findById called with null or blank firebaseUid");
            return Optional.empty();
        }

        try {
            var snapshot = firestore
                .collection(COLLECTION)
                .document(firebaseUid)
                .get()
                .get();

            if (!snapshot.exists()) {
                log.debug("No UserDocument found for uid: {}", firebaseUid);
                return Optional.empty();
            }

            UserDocument doc = snapshot.toObject(UserDocument.class);
            log.debug("Loaded UserDocument for uid: {}", firebaseUid);
            return Optional.ofNullable(doc);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while fetching UserDocument for uid: {}", firebaseUid, e);
            throw new RuntimeException("Firestore read interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to fetch UserDocument for uid: {}", firebaseUid, e);
            throw new RuntimeException("Firestore read failed", e);
        }
    }

    /**
     * Find a user by email address.
     * Performs a Firestore collection query — slightly slower than findById.
     * Prefer findById when the Firebase UID is available.
     *
     * @param email user's email address
     * @return Optional containing the UserDocument if found
     */
    public Optional<UserDocument> findByEmail(String email) {
        if (email == null || email.isBlank()) {
            log.warn("findByEmail called with null or blank email");
            return Optional.empty();
        }

        try {
            var results = firestore
                .collection(COLLECTION)
                .whereEqualTo("email", email)
                .limit(1)
                .get()
                .get();

            if (results.isEmpty()) {
                log.debug("No UserDocument found for email: {}", email);
                return Optional.empty();
            }

            UserDocument doc = results.getDocuments()
                .get(0)
                .toObject(UserDocument.class);

            log.debug("Loaded UserDocument for email: {}", email);
            return Optional.ofNullable(doc);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while fetching UserDocument by email: {}", email, e);
            throw new RuntimeException("Firestore read interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to fetch UserDocument by email: {}", email, e);
            throw new RuntimeException("Firestore read failed", e);
        }
    }

    /**
     * Check if a user document exists for the given Firebase UID.
     * Cheaper than findById when you only need existence, not the document.
     *
     * @param firebaseUid Firebase Auth UID
     * @return true if document exists
     */
    public boolean existsById(String firebaseUid) {
        if (firebaseUid == null || firebaseUid.isBlank()) return false;

        try {
            return firestore
                .collection(COLLECTION)
                .document(firebaseUid)
                .get()
                .get()
                .exists();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while checking existence for uid: {}", firebaseUid, e);
            throw new RuntimeException("Firestore read interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to check existence for uid: {}", firebaseUid, e);
            throw new RuntimeException("Firestore read failed", e);
        }
    }

    /* =========================
       READ — Collections / Queries
       ========================= */

    /**
     * Find all users at a specific approval level.
     * Used by admin endpoints to list users pending approval.
     *
     * @param approvalLevel ApprovalLevel.name() e.g. "PENDING_L1", "PENDING_L2"
     * @return list of matching UserDocuments
     */
    public List<UserDocument> findByApprovalLevel(String approvalLevel) {
        if (approvalLevel == null || approvalLevel.isBlank()) return List.of();

        try {
            var results = firestore
                .collection(COLLECTION)
                .whereEqualTo("approval_level", approvalLevel)
                .get()
                .get();

            List<UserDocument> docs = results.getDocuments()
                .stream()
                .map(snapshot -> snapshot.toObject(UserDocument.class))
                .filter(Objects::nonNull)
                .toList();

            log.debug("Found {} users with approval level: {}", docs.size(), approvalLevel);
            return docs;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while fetching users by approval level: {}", approvalLevel, e);
            throw new RuntimeException("Firestore read interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to fetch users by approval level: {}", approvalLevel, e);
            throw new RuntimeException("Firestore read failed", e);
        }
    }

    /**
     * Find all users with a specific status.
     * e.g. UserStatus.ACTIVE.name(), UserStatus.PENDING_APPROVAL.name()
     *
     * @param status UserStatus.name() string
     * @return list of matching UserDocuments
     */
    public List<UserDocument> findByStatus(String status) {
        if (status == null || status.isBlank()) return List.of();

        try {
            var results = firestore
                .collection(COLLECTION)
                .whereEqualTo("status", status)
                .get()
                .get();

            List<UserDocument> docs = results.getDocuments()
                .stream()
                .map(snapshot -> snapshot.toObject(UserDocument.class))
                .filter(Objects::nonNull)
                .toList();

            log.debug("Found {} users with status: {}", docs.size(), status);
            return docs;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while fetching users by status: {}", status, e);
            throw new RuntimeException("Firestore read interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to fetch users by status: {}", status, e);
            throw new RuntimeException("Firestore read failed", e);
        }
    }

    /**
     * Find all users holding a specific role.
     * Uses Firestore array-contains query on the roles list.
     *
     * @param roleName Roles.name() e.g. "ADMIN", "DESIGNER"
     * @return list of matching UserDocuments
     */
    public List<UserDocument> findByRole(String roleName) {
        if (roleName == null || roleName.isBlank()) return List.of();

        try {
            var results = firestore
                .collection(COLLECTION)
                .whereArrayContains("roles", roleName)
                .get()
                .get();

            List<UserDocument> docs = results.getDocuments()
                .stream()
                .map(snapshot -> snapshot.toObject(UserDocument.class))
                .filter(Objects::nonNull)
                .toList();

            log.debug("Found {} users with role: {}", docs.size(), roleName);
            return docs;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while fetching users by role: {}", roleName, e);
            throw new RuntimeException("Firestore read interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to fetch users by role: {}", roleName, e);
            throw new RuntimeException("Firestore read failed", e);
        }
    }

    /**
     * Find all enabled users.
     * Used for bulk operations and analytics.
     *
     * @return list of all active UserDocuments
     */
    public List<UserDocument> findAllEnabled() {
        try {
            var results = firestore
                .collection(COLLECTION)
                .whereEqualTo("enabled", true)
                .get()
                .get();

            List<UserDocument> docs = results.getDocuments()
                .stream()
                .map(snapshot -> snapshot.toObject(UserDocument.class))
                .filter(Objects::nonNull)
                .toList();

            log.debug("Found {} enabled users", docs.size());
            return docs;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while fetching enabled users", e);
            throw new RuntimeException("Firestore read interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to fetch enabled users", e);
            throw new RuntimeException("Firestore read failed", e);
        }
    }

    /**
     * Count users at a specific approval level.
     * Lighter than findByApprovalLevel when only count is needed.
     *
     * @param approvalLevel ApprovalLevel.name()
     * @return count of matching documents
     */
    public int countByApprovalLevel(String approvalLevel) {
        return findByApprovalLevel(approvalLevel).size();
    }

    /* =========================
       WRITE
       ========================= */

    /**
     * Save a UserDocument to Firestore.
     * Performs a full document overwrite.
     *
     * Use for:
     *   - Creating new users
     *   - Full document updates after assembling all fields
     *
     * Always sets updatedAt to now before writing.
     *
     * @param userDocument the document to save
     * @return the saved document (with updatedAt set)
     */
    public UserDocument save(UserDocument userDocument) {
        if (userDocument == null) {
            throw new IllegalArgumentException("UserDocument cannot be null");
        }
        if (userDocument.getId() == null || userDocument.getId().isBlank()) {
            throw new IllegalArgumentException(
                "UserDocument must have an ID (Firebase UID) before saving");
        }

        try {
            userDocument.setUpdatedAt(Instant.now());

            firestore
                .collection(COLLECTION)
                .document(userDocument.getId())
                .set(userDocument)
                .get();

            log.debug("Saved UserDocument: {}", userDocument.getId());
            return userDocument;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while saving UserDocument: {}", userDocument.getId(), e);
            throw new RuntimeException("Firestore write interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to save UserDocument: {}", userDocument.getId(), e);
            throw new RuntimeException("Firestore write failed", e);
        }
    }

    /**
     * Partial update — merges only the provided fields into the document.
     *
     * Use for:
     *   - Single field updates (e.g. lastLogin, failedLoginAttempts)
     *   - Avoiding overwrite of fields not loaded into memory
     *
     * Always adds updated_at to the provided fields map.
     *
     * @param firebaseUid document ID
     * @param fields      map of Firestore field names → new values
     */
    public void updateFields(String firebaseUid, Map<String, Object> fields) {
        if (firebaseUid == null || firebaseUid.isBlank()) {
            throw new IllegalArgumentException("firebaseUid cannot be null or blank");
        }
        if (fields == null || fields.isEmpty()) {
            log.warn("updateFields called with empty fields map for uid: {}", firebaseUid);
            return;
        }

        try {
            // Always stamp the update time
            Map<String, Object> fieldsWithTimestamp = new java.util.HashMap<>(fields);
            fieldsWithTimestamp.put("updated_at", Instant.now());

            firestore
                .collection(COLLECTION)
                .document(firebaseUid)
                .set(fieldsWithTimestamp, SetOptions.merge())
                .get();

            log.debug("Partial update applied to UserDocument: {} — fields: {}",
                firebaseUid, fields.keySet());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while updating fields for uid: {}", firebaseUid, e);
            throw new RuntimeException("Firestore write interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed to update fields for uid: {}", firebaseUid, e);
            throw new RuntimeException("Firestore write failed", e);
        }
    }

    /**
     * Convenience overload — update a single field.
     *
     * @param firebaseUid document ID
     * @param fieldName   Firestore field name
     * @param value       new value
     */
    public void updateField(String firebaseUid, String fieldName, Object value) {
        updateFields(firebaseUid, Map.of(fieldName, value));
    }

    /* =========================
       ACCOUNT STATE SHORTCUTS
       ========================= */

    /**
     * Record a successful login.
     * Updates login tracking fields without loading the full document.
     *
     * @param firebaseUid   user's Firebase UID
     * @param ip            client IP address
     * @param userAgent     client user agent string
     * @param now           login timestamp
     */
    public void recordLogin(String firebaseUid,
                             String ip,
                             String userAgent,
                             Instant now) {
        updateFields(firebaseUid, Map.of(
            "last_login",            now,
            "last_login_ip",         ip != null ? ip : "",
            "last_login_user_agent", userAgent != null ? userAgent : "",
            "failed_login_attempts", 0
        ));
        log.debug("Recorded login for uid: {} from ip: {}", firebaseUid, ip);
    }

    /**
     * Increment failed login attempts counter.
     *
     * Note: Firestore does not support atomic increment on custom objects.
     * This reads the current count, increments it, and writes back.
     * Under high concurrency, prefer Firestore FieldValue.increment() via
     * a raw DocumentReference update instead.
     *
     * @param firebaseUid user's Firebase UID
     * @param now         timestamp of the failed attempt
     */
    public void recordFailedLogin(String firebaseUid, Instant now) {
        try {
            // Use Firestore FieldValue for atomic increment
            firestore
                .collection(COLLECTION)
                .document(firebaseUid)
                .update(
                    "failed_login_attempts",
                    com.google.cloud.firestore.FieldValue.increment(1),
                    "updated_at", now
                )
                .get();

            log.debug("Recorded failed login for uid: {}", firebaseUid);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Firestore write interrupted", e);
        } catch (ExecutionException e) {
            log.error("Failed to record failed login for uid: {}", firebaseUid, e);
            throw new RuntimeException("Firestore write failed", e);
        }
    }

    /**
     * Lock a user account until a specific time.
     *
     * @param firebaseUid        user's Firebase UID
     * @param lockedUntil        when the lock expires
     * @param lockReason         human-readable reason
     * @param lockType           SecurityMetadata.LockType.name()
     */
    public void lockAccount(String firebaseUid,
                             Instant lockedUntil,
                             String lockReason,
                             String lockType) {
        updateFields(firebaseUid, Map.of(
            "account_locked",       true,
            "account_locked_until", lockedUntil,
            "lock_reason",          lockReason != null ? lockReason : "",
            "lock_type",            lockType != null ? lockType : "",
            "status",               com.techStack.authSys.models.user.UserStatus.LOCKED.name()
        ));
        log.info("Locked account for uid: {} until: {} reason: {}",
            firebaseUid, lockedUntil, lockReason);
    }

    /**
     * Unlock a user account.
     *
     * @param firebaseUid user's Firebase UID
     */
    public void unlockAccount(String firebaseUid) {
        updateFields(firebaseUid, Map.of(
            "account_locked",       false,
            "account_locked_until", com.google.cloud.firestore.FieldValue.delete(),
            "lock_reason",          "",
            "lock_type",            "",
            "failed_login_attempts", 0,
            "status",               com.techStack.authSys.models.user.UserStatus.ACTIVE.name()
        ));
        log.info("Unlocked account for uid: {}", firebaseUid);
    }

    /**
     * Update a user's approval state.
     *
     * @param firebaseUid   user's Firebase UID
     * @param status        new UserStatus.name()
     * @param approvalLevel new ApprovalLevel.name()
     * @param enabled       whether the account should be enabled
     * @param approvedBy    UID of the approver (null if rejecting)
     * @param now           timestamp
     */
    public void updateApprovalState(String firebaseUid,
                                     String status,
                                     String approvalLevel,
                                     boolean enabled,
                                     String approvedBy,
                                     Instant now) {
        Map<String, Object> fields = new java.util.HashMap<>();
        fields.put("status",         status);
        fields.put("approval_level", approvalLevel);
        fields.put("enabled",        enabled);
        fields.put("approved_at",    now);

        if (approvedBy != null) {
            fields.put("approved_by", approvedBy);
        }

        updateFields(firebaseUid, fields);
        log.info("Updated approval state for uid: {} → status: {} level: {}",
            firebaseUid, status, approvalLevel);
    }

    /* =========================
       DELETE
       ========================= */

    /**
     * Soft delete — sets status to DEACTIVATED and disables the account.
     * Hard deletes are never performed in production.
     *
     * The document remains in Firestore for audit purposes.
     * FirebaseAuth account should be disabled separately via FirebaseAuth.updateUser().
     *
     * @param firebaseUid user's Firebase UID
     */
    public void softDelete(String firebaseUid) {
        updateFields(firebaseUid, Map.of(
            "status",  com.techStack.authSys.models.user.UserStatus.DEACTIVATED.name(),
            "enabled", false
        ));
        log.info("Soft deleted UserDocument: {}", firebaseUid);
    }

    /**
     * Restore a soft-deleted user account.
     * Sets status back to PENDING_APPROVAL — must go through approval again.
     *
     * @param firebaseUid user's Firebase UID
     */
    public void restore(String firebaseUid) {
        updateFields(firebaseUid, Map.of(
            "status",         com.techStack.authSys.models.user.UserStatus.PENDING_APPROVAL.name(),
            "approval_level", com.techStack.authSys.models.user.ApprovalLevel.PENDING_L1.name(),
            "enabled",        false
        ));
        log.info("Restored UserDocument: {} — pending re-approval", firebaseUid);
    }

    /* =========================
       BATCH OPERATIONS
       ========================= */

    /**
     * Save multiple UserDocuments in a single Firestore batch write.
     * More efficient than calling save() in a loop.
     *
     * Firestore batch limit: 500 documents per batch.
     * This method automatically splits into multiple batches if needed.
     *
     * @param documents list of UserDocuments to save
     */
    public void saveAll(List<UserDocument> documents) {
        if (documents == null || documents.isEmpty()) return;

        Instant now = Instant.now();
        int batchSize = 500;

        try {
            for (int i = 0; i < documents.size(); i += batchSize) {
                List<UserDocument> batch = documents.subList(
                    i, Math.min(i + batchSize, documents.size()));

                var writeBatch = firestore.batch();

                for (UserDocument doc : batch) {
                    if (doc.getId() == null || doc.getId().isBlank()) {
                        log.warn("Skipping UserDocument with null ID in saveAll");
                        continue;
                    }
                    doc.setUpdatedAt(now);
                    var ref = firestore.collection(COLLECTION).document(doc.getId());
                    writeBatch.set(ref, doc);
                }

                writeBatch.commit().get();
                log.debug("Batch saved {} documents", batch.size());
            }

            log.info("saveAll completed: {} total documents saved", documents.size());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted during saveAll", e);
            throw new RuntimeException("Firestore batch write interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed during saveAll", e);
            throw new RuntimeException("Firestore batch write failed", e);
        }
    }

    /**
     * Fetch multiple UserDocuments by their Firebase UIDs.
     * Uses Firestore's whereIn query — limited to 30 UIDs per call.
     *
     * For larger sets, split into chunks of 30 and call multiple times.
     *
     * @param firebaseUids list of Firebase UIDs (max 30)
     * @return list of found UserDocuments (may be smaller than input if some not found)
     */
    public List<UserDocument> findAllByIds(List<String> firebaseUids) {
        if (firebaseUids == null || firebaseUids.isEmpty()) return List.of();

        if (firebaseUids.size() > 30) {
            log.warn("findAllByIds called with {} UIDs — Firestore whereIn limit is 30. " +
                "Truncating to first 30.", firebaseUids.size());
        }

        List<String> limitedUids = firebaseUids.stream().limit(30).toList();

        try {
            var results = firestore
                .collection(COLLECTION)
                .whereIn(com.google.cloud.firestore.FieldPath.documentId(), limitedUids)
                .get()
                .get();

            return results.getDocuments()
                .stream()
                .map(snapshot -> snapshot.toObject(UserDocument.class))
                .filter(Objects::nonNull)
                .toList();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted during findAllByIds", e);
            throw new RuntimeException("Firestore read interrupted", e);

        } catch (ExecutionException e) {
            log.error("Failed during findAllByIds", e);
            throw new RuntimeException("Firestore read failed", e);
        }
    }
}