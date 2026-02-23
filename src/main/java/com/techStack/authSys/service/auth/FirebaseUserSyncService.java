package com.techStack.authSys.service.auth;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.models.user.*;
import com.techStack.authSys.repository.authorization.FirestoreUserPermissionsRepository;
import com.techStack.authSys.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

/**
 * Keeps Firebase Auth, Firestore (UserDocument), and PostgreSQL (UserEntity) in sync.
 *
 * Called on every authenticated request via FirebaseTokenFilter.
 * Handles three cases:
 *   1. Brand new user    → create UserDocument in Firestore
 *                        + user_permissions document
 *                        + UserEntity in PostgreSQL
 *   2. Existing user     → update lastLoginAt in PostgreSQL only
 *   3. Deactivated user  → block login
 *
 * Model split (why this changed):
 *   The old service called firestore.collection("users").set(user) where user
 *   was the dual-annotated User class. Spring Data Firestore rejected this because
 *   User contained Map<String,Object>, SecurityMetadata inner classes, and
 *   Set<> fields — all illegal for Spring Data Firestore serialization.
 *
 *   UserDocument  → Firestore collection "users" (Firestore-safe types only)
 *   UserEntity    → PostgreSQL table "users" (relational anchor, FK target)
 *   User          → domain model (assembled by UserAssembler, not persisted here)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FirebaseUserSyncService {

    private final FirebaseAuth firebaseAuth;
    private final UserRepository userRepository;                      // JPA → UserEntity
    private final FirestoreUserPermissionsRepository permissionsRepo; // Firestore
    private final com.google.cloud.firestore.Firestore firestore;
    private final Clock clock;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Main sync entry point — call this on every authenticated request.
     *
     * Returns UserDocument from Firestore. Callers that need the full
     * domain User object should pass this to UserAssembler.fromDocument().
     *
     * @param firebaseUid the UID from the verified Firebase JWT
     * @return the synced UserDocument
     */
    @Transactional  // covers PostgreSQL write only
    public UserDocument syncUser(String firebaseUid) {
        try {
            Optional<UserDocument> existing = findDocumentInFirestore(firebaseUid);

            if (existing.isPresent()) {
                UserDocument doc = existing.get();

                if (!doc.isActive()) {
                    log.warn("Blocked login for non-active user: {} (status={})",
                            firebaseUid, doc.getStatus());
                    throw new IllegalStateException(
                            "Account is not active. Status: " + doc.getStatus());
                }

                // Lightweight update — PostgreSQL only, no Firestore write on every login
                userRepository.updateLastLogin(firebaseUid, clock.instant());
                log.debug("Returning existing user: {}", firebaseUid);
                return doc;
            }

            log.info("New user detected, creating records for uid: {}", firebaseUid);
            return createNewUser(firebaseUid);

        } catch (IllegalStateException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("syncUser interrupted for uid: {}", firebaseUid, e);
            throw new RuntimeException("User sync interrupted. Please try again.", e);
        } catch (Exception e) {
            log.error("User sync failed for uid: {}", firebaseUid, e);
            throw new RuntimeException("User sync failed. Please try again.", e);
        }
    }

    /**
     * Called by Firebase webhook or admin action on account deletion.
     * Soft-deletes the user in both PostgreSQL and Firestore.
     */
    @Transactional
    public void handleUserDeletion(String firebaseUid) {
        Instant now = clock.instant();

        // Soft delete in PostgreSQL — UserEntity.deactivate() exists
        userRepository.findByFirebaseUid(firebaseUid).ifPresent(entity -> {
            entity.deactivate();
            userRepository.save(entity);
            log.debug("Soft-deleted UserEntity for uid: {}", firebaseUid);
        });

        // Soft delete in Firestore — mutate UserDocument directly
        findDocumentInFirestore(firebaseUid).ifPresent(doc -> {
            doc.setUserStatus(UserStatus.DEACTIVATED);
            doc.setEnabled(false);
            doc.setAccountDisabled(true);
            doc.setUpdatedAt(now);
            saveDocumentToFirestore(doc);
            log.debug("Soft-deleted UserDocument for uid: {}", firebaseUid);
        });

        permissionsRepo.deleteBlocking(firebaseUid);
        log.info("Deactivated user on deletion: {}", firebaseUid);
    }

    // -------------------------------------------------------------------------
    // Private — new user creation
    // -------------------------------------------------------------------------

    /**
     * Creates all persistence records for a brand new user.
     *
     * Order matters:
     *   1. Build UserDocument via factory method
     *   2. Save UserDocument to Firestore (primary store)
     *   3. Create user_permissions document (blocking — must exist before return)
     *   4. Save UserEntity to PostgreSQL (relational anchor)
     */
    private UserDocument createNewUser(String firebaseUid)
            throws FirebaseAuthException, ExecutionException, InterruptedException {

        UserRecord firebaseUser = firebaseAuth.getUser(firebaseUid);
        Instant now = clock.instant();

        // Build UserDocument using the factory — sets sensible defaults
        UserDocument doc = UserDocument.defaultFor(
                firebaseUid,
                firebaseUser.getEmail(),
                extractFirstName(firebaseUser.getDisplayName()),
                extractLastName(firebaseUser.getDisplayName()),
                now
        );

        // Populate additional fields available at registration time
        doc.setPhoneNumber(firebaseUser.getPhoneNumber());
        doc.setProfilePictureUrl(firebaseUser.getPhotoUrl());
        doc.setEmailVerified(firebaseUser.isEmailVerified());

        // Save UserDocument to Firestore — Firestore-safe types only
        saveDocumentToFirestore(doc);

        // Create default user_permissions — blocking because we are in a
        // servlet context and the document must exist before method returns
        permissionsRepo.createDefaultBlocking(firebaseUid);

        // Save lean relational anchor to PostgreSQL
        saveEntityToPostgres(doc, now);

        log.info("Created new user: {} ({})", firebaseUid, doc.getEmail());
        return doc;
    }

    // -------------------------------------------------------------------------
    // Private — Firestore helpers
    // -------------------------------------------------------------------------

    /**
     * Reads a UserDocument from Firestore by Firebase UID.
     */
    private Optional<UserDocument> findDocumentInFirestore(String firebaseUid) {
        try {
            var snapshot = firestore
                    .collection("users")
                    .document(firebaseUid)
                    .get()
                    .get();

            if (!snapshot.exists()) return Optional.empty();

            // toObject(UserDocument.class) — Firestore-safe types, no Spring Data rejection
            UserDocument doc = snapshot.toObject(UserDocument.class);
            if (doc == null) {
                log.warn("Firestore deserialized null UserDocument for uid: {}", firebaseUid);
                return Optional.empty();
            }

            return Optional.of(doc);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Firestore read interrupted for uid: " + firebaseUid, e);
        } catch (ExecutionException e) {
            log.error("Firestore read failed for uid: {}", firebaseUid, e);
            throw new RuntimeException("Failed to read UserDocument from Firestore", e);
        }
    }

    /**
     * Writes a UserDocument to Firestore using full set() — not merge.
     */
    private void saveDocumentToFirestore(UserDocument doc) {
        try {
            firestore
                    .collection("users")
                    .document(doc.getId())
                    .set(doc)
                    .get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(
                    "Firestore write interrupted for uid: " + doc.getId(), e);
        } catch (ExecutionException e) {
            log.error("Failed to save UserDocument to Firestore: {}", doc.getId(), e);
            throw new RuntimeException("Firestore write failed for uid: " + doc.getId(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Private — PostgreSQL helpers
    // -------------------------------------------------------------------------

    /**
     * Saves a relational anchor UserEntity to PostgreSQL.
     *
     * Only relational fields are populated — full state lives in Firestore.
     * Idempotent — no-ops if the firebaseUid already has a record.
     */
    private void saveEntityToPostgres(UserDocument doc, Instant now) {
        if (userRepository.existsByFirebaseUid(doc.getId())) {
            log.debug("UserEntity already exists for uid: {} — skipping", doc.getId());
            return;
        }

        UserEntity entity = UserEntity.builder()
                .firebaseUid(doc.getId())
                .email(doc.getEmail())
                .firstName(doc.getFirstName())
                .lastName(doc.getLastName())
                .username(doc.getUsername())
                .phoneNumber(doc.getPhoneNumber())
                .profilePictureUrl(doc.getProfilePictureUrl())
                .status(doc.getUserStatus())
                .approvalLevel(doc.getApprovalLevelEnum())
                .enabled(doc.isEnabled())
                .emailVerified(doc.isEmailVerified())
                .createdAt(now)
                .updatedAt(now)
                .build();

        userRepository.save(entity);
        log.debug("Saved UserEntity for uid: {}", doc.getId());
    }

    // -------------------------------------------------------------------------
    // Private — utilities
    // -------------------------------------------------------------------------

    private String extractFirstName(String displayName) {
        if (displayName == null || displayName.isBlank()) return "";
        return displayName.trim().split("\\s+", 2)[0];
    }

    private String extractLastName(String displayName) {
        if (displayName == null || displayName.isBlank()) return "";
        String[] parts = displayName.trim().split("\\s+", 2);
        return parts.length > 1 ? parts[1] : "";
    }
}