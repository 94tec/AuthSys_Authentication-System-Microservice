package com.techStack.authSys.service.auth;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.models.user.ApprovalLevel;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
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
 * Keeps Firebase Auth, Firestore, and PostgreSQL in sync.
 *
 * Called on every authenticated request via FirebaseTokenFilter.
 * Handles three cases:
 *   1. Brand new user    → create in Firestore + PostgreSQL + user_permissions
 *   2. Existing user     → update lastLogin only
 *   3. Deactivated user  → block login
 *
 * Threading note:
 *   This service runs in a servlet/blocking context (called from a filter).
 *   All Firestore calls block here deliberately — the filter chain is already
 *   on a bounded thread. Reactive wrappers are not used here; instead we
 *   call the *Blocking variants of our repositories where available.
 *
 * Clock note:
 *   Instant.now() has been replaced throughout with clock.instant() so
 *   that tests can control the current time without mocking static methods.
 *
 * Deactivation note:
 *   User.deactivate() does not exist on the User domain model. Deactivation
 *   is modelled as setting status=DEACTIVATED + enabled=false, which aligns
 *   with the existing User.lockAccount() / UserStatus enum pattern.
 *
 * UserJpaProjection note:
 *   The original saveUserToPostgres() built a UserJpaProjection that does
 *   not exist. User itself is the @Entity — we save it directly to JPA.
 *   Only the fields relevant to the relational anchor are populated.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FirebaseUserSyncService {

    private final FirebaseAuth firebaseAuth;
    private final UserRepository userRepository;
    private final FirestoreUserPermissionsRepository permissionsRepo;
    private final com.google.cloud.firestore.Firestore firestore;
    private final Clock clock;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Main sync entry point — call this on every authenticated request.
     *
     * @param firebaseUid the UID from the verified Firebase JWT
     * @return the synced User object (read from Firestore)
     * @throws IllegalStateException if the account is deactivated or pending
     * @throws RuntimeException      if Firestore or Firebase is unreachable
     */
    @Transactional  // covers the PostgreSQL write only
    public User syncUser(String firebaseUid) {
        try {
            Optional<User> existingUser = findInFirestore(firebaseUid);

            if (existingUser.isPresent()) {
                User user = existingUser.get();

                if (!user.isActive()) {
                    log.warn("Blocked login for non-active user: {} (status={})",
                            firebaseUid, user.getStatus());
                    throw new IllegalStateException(
                            "Account is not active. Status: " + user.getStatus());
                }

                // Lightweight update — PostgreSQL only, no Firestore write
                userRepository.updateLastLogin(firebaseUid, clock.instant());
                log.debug("Returning existing user: {}", firebaseUid);
                return user;
            }

            log.info("New user detected, creating records for uid: {}", firebaseUid);
            return createNewUser(firebaseUid);

        } catch (IllegalStateException e) {
            throw e; // re-throw account state errors as-is
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // restore interrupt flag
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
     *
     * @param firebaseUid the Firebase UID of the deleted account
     */
    @Transactional
    public void handleUserDeletion(String firebaseUid) {
        Instant now = clock.instant();

        // Soft delete in PostgreSQL
        userRepository.findByFirebaseUid(firebaseUid).ifPresent(user -> {
            deactivateUser(user, now);
            userRepository.save(user);
            log.debug("Soft-deleted user in PostgreSQL: {}", firebaseUid);
        });

        // Soft delete in Firestore
        findInFirestore(firebaseUid).ifPresent(user -> {
            deactivateUser(user, now);
            saveUserToFirestore(user);
            log.debug("Soft-deleted user in Firestore: {}", firebaseUid);
        });

        // Remove permissions document
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
     *   1. Build User domain object
     *   2. Save to Firestore (primary store)
     *   3. Create user_permissions document (blocking — must complete before return)
     *   4. Save lightweight anchor to PostgreSQL
     */
    private User createNewUser(String firebaseUid)
            throws FirebaseAuthException, ExecutionException, InterruptedException {

        UserRecord firebaseUser = firebaseAuth.getUser(firebaseUid);
        Instant now = clock.instant();

        // 1. Build User domain object
        User newUser = User.builder()
                .id(firebaseUid)
                .firebaseUid(firebaseUid)
                .email(firebaseUser.getEmail())
                .firstName(extractFirstName(firebaseUser.getDisplayName()))
                .lastName(extractLastName(firebaseUser.getDisplayName()))
                .phoneNumber(firebaseUser.getPhoneNumber())
                .profilePictureUrl(firebaseUser.getPhotoUrl())
                .status(UserStatus.PENDING_APPROVAL)
                .enabled(false)
                .emailVerified(firebaseUser.isEmailVerified())
                .approvalLevel(ApprovalLevel.PENDING_L1)
                .createdAt(now)
                .updatedAt(now)
                .build();

        newUser.addRole(Roles.USER);

        // 2. Save User document to Firestore
        saveUserToFirestore(newUser);

        // 3. Create default user_permissions document in Firestore.
        //
        //    Fix from original: permissionsRepo.createDefault() returns Mono<> —
        //    the original called it without subscribing, meaning the write never
        //    executed. We use the blocking variant here since we are already in
        //    a blocking servlet context and need the document to exist before
        //    this method returns.
        permissionsRepo.createDefaultBlocking(firebaseUid);

        // 4. Save relational anchor to PostgreSQL
        saveUserToPostgres(newUser, now);

        log.info("Created new user: {} ({})", firebaseUid, newUser.getEmail());
        return newUser;
    }

    // -------------------------------------------------------------------------
    // Private — persistence helpers
    // -------------------------------------------------------------------------

    /**
     * Reads a User document from Firestore by Firebase UID.
     *
     * @param firebaseUid the document ID (= Firebase UID)
     * @return Optional containing the User if found, empty if not
     */
    private Optional<User> findInFirestore(String firebaseUid) {
        try {
            var doc = firestore
                    .collection("users")
                    .document(firebaseUid)
                    .get()
                    .get();

            if (!doc.exists()) return Optional.empty();

            User user = doc.toObject(User.class);
            if (user == null) {
                log.warn("Firestore returned null deserialization for uid: {}", firebaseUid);
                return Optional.empty();
            }

            return Optional.of(user);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted reading user from Firestore: {}", firebaseUid, e);
            throw new RuntimeException("Firestore read interrupted for uid: " + firebaseUid, e);

        } catch (ExecutionException e) {
            log.error("Firestore read failed for uid: {}", firebaseUid, e);
            throw new RuntimeException("Failed to read user from Firestore", e);
        }
    }

    /**
     * Writes a User document to Firestore using a full set() (not merge).
     *
     * @param user the user to persist
     */
    private void saveUserToFirestore(User user) {
        try {
            firestore
                    .collection("users")
                    .document(user.getFirebaseUid())
                    .set(user) // full replace — not merge
                    .get();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted saving user to Firestore: {}", user.getFirebaseUid(), e);
            throw new RuntimeException(
                    "Firestore write interrupted for uid: " + user.getFirebaseUid(), e);

        } catch (ExecutionException e) {
            log.error("Failed to save user to Firestore: {}", user.getFirebaseUid(), e);
            throw new RuntimeException("Firestore write failed", e);
        }
    }

    /**
     * Saves a relational anchor record to PostgreSQL.
     *
     * The full user object lives in Firestore. PostgreSQL holds only the
     * fields needed for relational joins (orders, projects, audit logs, etc.).
     *
     * Fix from original: the original built a non-existent UserJpaProjection.
     * User is the @Entity — we save it directly. Only relational-relevant
     * fields are set; Firestore-only fields are left at their defaults.
     *
     * Idempotent — no-ops if a record for this firebaseUid already exists.
     *
     * @param user the user domain object (already saved to Firestore)
     * @param now  current instant for audit timestamps
     */
    private void saveUserToPostgres(User user, Instant now) {
        if (userRepository.existsByFirebaseUid(user.getFirebaseUid())) {
            log.debug("PostgreSQL record already exists for uid: {} — skipping",
                    user.getFirebaseUid());
            return;
        }

        // Build a minimal JPA-persisted User with only the relational fields.
        // The full user state (roles, permissions, security metadata) lives in Firestore.
        User pgUser = User.builder()
                .firebaseUid(user.getFirebaseUid())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .phoneNumber(user.getPhoneNumber())
                .status(user.getStatus())
                .enabled(user.isEnabled())
                .approvalLevel(user.getApprovalLevel())
                .createdAt(now)
                .updatedAt(now)
                .build();

        userRepository.save(pgUser);
        log.debug("Saved PostgreSQL anchor for uid: {}", user.getFirebaseUid());
    }

    // -------------------------------------------------------------------------
    // Private — domain state helpers
    // -------------------------------------------------------------------------

    /**
     * Applies deactivation state to a User object.
     *
     * Fix from original: User.deactivate() does not exist. Deactivation is
     * modelled as status=DEACTIVATED + enabled=false, consistent with
     * the UserStatus enum and the existing lockAccount() pattern.
     *
     * @param user the user to deactivate (mutated in place)
     * @param now  current instant for the updatedAt timestamp
     */
    private void deactivateUser(User user, Instant now) {
        user.setStatus(UserStatus.DEACTIVATED);
        user.setEnabled(false);
        user.setAccountDisabled(true);
        user.setUpdatedAt(now);
    }

    // -------------------------------------------------------------------------
    // Private — utilities
    // -------------------------------------------------------------------------

    /**
     * Extracts the first name from a Firebase display name.
     * e.g. "Jane Doe" → "Jane", "Madonna" → "Madonna", null → ""
     */
    private String extractFirstName(String displayName) {
        if (displayName == null || displayName.isBlank()) return "";
        return displayName.trim().split("\\s+", 2)[0];
    }

    /**
     * Extracts the last name from a Firebase display name.
     * e.g. "Jane Doe" → "Doe", "Madonna" → "", null → ""
     */
    private String extractLastName(String displayName) {
        if (displayName == null || displayName.isBlank()) return "";
        String[] parts = displayName.trim().split("\\s+", 2);
        return parts.length > 1 ? parts[1] : "";
    }
}