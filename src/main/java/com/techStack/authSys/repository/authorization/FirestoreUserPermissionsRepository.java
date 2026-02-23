package com.techStack.authSys.repository.authorization;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.SetOptions;
import com.techStack.authSys.models.firestore.FirestoreUserPermissions;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.util.Optional;

/**
 * Repository for reading and writing user-level permission documents from Firestore.
 *
 * Collection: user_permissions/{firebaseUid}
 *
 * One document per user. This is the single read that AuthService uses to
 * build a user's JWT — it contains their roles, explicit grants, and explicit
 * denials. See FirestoreUserPermissions for the document structure.
 *
 * Save strategy:
 *   We use set() WITHOUT SetOptions.merge() for full document writes.
 *   merge() is dangerous here because it cannot clear list fields —
 *   if a user had ["portfolio:publish"] in grants and we remove it,
 *   merge() would leave the stale entry in Firestore. Full set() replaces
 *   the document atomically, which is the correct behaviour for a document
 *   that owns its entire field set.
 *
 *   For partial field updates (e.g. only updating updatedAt), use
 *   Firestore's update() via a dedicated method rather than abusing merge().
 *
 * Blocking I/O note:
 *   All methods that touch Firestore are available in both reactive
 *   (Mono-returning) and blocking variants. Reactive variants wrap
 *   the blocking SDK call in Mono.fromCallable() on Schedulers.boundedElastic().
 *   Blocking variants are explicitly named *Blocking and must only be called
 *   from within an already-scheduled boundedElastic context.
 */
@Repository
@RequiredArgsConstructor
@Slf4j
public class FirestoreUserPermissionsRepository {

    private final Firestore firestore;
    private final Clock clock;

    private static final String COLLECTION = "user_permissions";

    // -------------------------------------------------------------------------
    // Read — reactive
    // -------------------------------------------------------------------------

    /**
     * Finds a user's permission document by Firebase UID, reactively.
     *
     * Returns Mono.empty() if the document does not exist, allowing
     * callers to use switchIfEmpty() to handle the new-user case.
     *
     * @param firebaseUid Firebase Auth UID
     * @return Mono emitting the document if found, empty if not found
     */
    public Mono<FirestoreUserPermissions> findByFirebaseUid(String firebaseUid) {
        if (firebaseUid == null || firebaseUid.isBlank()) {
            return Mono.error(new IllegalArgumentException(
                    "firebaseUid must not be null or blank"));
        }

        return Mono.fromCallable(() -> {
                    var doc = firestore
                            .collection(COLLECTION)
                            .document(firebaseUid)
                            .get()
                            .get(); // blocking — safe on boundedElastic

                    if (!doc.exists()) {
                        log.debug("No user_permissions document found for uid: {}", firebaseUid);
                        return null; // Mono.fromCallable null → Mono.empty()
                    }

                    FirestoreUserPermissions result = doc.toObject(FirestoreUserPermissions.class);
                    if (result == null) {
                        log.warn("Firestore returned null deserialization for uid: {}", firebaseUid);
                        return null;
                    }

                    log.debug("Loaded user_permissions for uid: {} — roles={}, grants={}, denials={}",
                            firebaseUid,
                            result.getRoles().size(),
                            result.getGrants().size(),
                            result.getDenials().size());

                    return result;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> log.error(
                        "Failed to fetch user_permissions for uid {}: {}",
                        firebaseUid, e.getMessage(), e))
                .onErrorMap(e -> new RuntimeException(
                        "Firestore read failed for uid: " + firebaseUid, e));
    }

    // -------------------------------------------------------------------------
    // Read — blocking
    // -------------------------------------------------------------------------

    /**
     * Blocking variant of findByFirebaseUid.
     *
     * Only call this from within a Mono.fromCallable() block that is already
     * subscribed on Schedulers.boundedElastic(). Never call from a Reactor
     * event-loop thread.
     *
     * @param firebaseUid Firebase Auth UID
     * @return Optional containing the document if found, empty if not found
     */
    public Optional<FirestoreUserPermissions> findByFirebaseUidBlocking(String firebaseUid) {
        if (firebaseUid == null || firebaseUid.isBlank()) {
            throw new IllegalArgumentException("firebaseUid must not be null or blank");
        }

        try {
            var doc = firestore
                    .collection(COLLECTION)
                    .document(firebaseUid)
                    .get()
                    .get();

            if (!doc.exists()) {
                log.debug("No user_permissions document found for uid: {}", firebaseUid);
                return Optional.empty();
            }

            FirestoreUserPermissions result = doc.toObject(FirestoreUserPermissions.class);
            if (result == null) {
                log.warn("Firestore returned null deserialization for uid: {}", firebaseUid);
                return Optional.empty();
            }

            return Optional.of(result);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // restore interrupt flag
            log.error("Interrupted while fetching user_permissions for uid: {}", firebaseUid, e);
            throw new RuntimeException("Firestore read interrupted for uid: " + firebaseUid, e);

        } catch (Exception e) {
            log.error("Failed to fetch user_permissions for uid {}: {}",
                    firebaseUid, e.getMessage(), e);
            throw new RuntimeException("Firestore read failed for uid: " + firebaseUid, e);
        }
    }

    // -------------------------------------------------------------------------
    // Write — reactive
    // -------------------------------------------------------------------------

    /**
     * Saves a user's permission document to Firestore, reactively.
     *
     * Uses full set() (NOT merge) to ensure stale grants/denials/roles
     * are overwritten rather than left behind. Sets updatedAt from the
     * injected Clock before writing.
     *
     * @param userPermissions the document to save
     * @return Mono emitting the saved document
     */
    public Mono<FirestoreUserPermissions> save(FirestoreUserPermissions userPermissions) {
        if (userPermissions == null) {
            return Mono.error(new IllegalArgumentException("userPermissions must not be null"));
        }
        if (userPermissions.getFirebaseUid() == null
                || userPermissions.getFirebaseUid().isBlank()) {
            return Mono.error(new IllegalArgumentException(
                    "userPermissions.firebaseUid must not be null or blank"));
        }

        userPermissions.setUpdatedAt(clock.instant());

        return Mono.fromCallable(() -> {
                    firestore
                            .collection(COLLECTION)
                            .document(userPermissions.getFirebaseUid())
                            .set(userPermissions) // full replace — NOT merge
                            .get();               // blocking — safe on boundedElastic
                    return userPermissions;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(saved -> log.info(
                        "Saved user_permissions for uid: {} — roles={}, grants={}, denials={}",
                        saved.getFirebaseUid(),
                        saved.getRoles().size(),
                        saved.getGrants().size(),
                        saved.getDenials().size()))
                .doOnError(e -> log.error(
                        "Failed to save user_permissions for uid {}: {}",
                        userPermissions.getFirebaseUid(), e.getMessage(), e))
                .onErrorMap(e -> new RuntimeException(
                        "Firestore write failed for uid: " + userPermissions.getFirebaseUid(), e));
    }

    // -------------------------------------------------------------------------
    // Write — blocking
    // -------------------------------------------------------------------------

    /**
     * Blocking variant of save.
     *
     * Only call from within a Mono.fromCallable() block on boundedElastic.
     *
     * @param userPermissions the document to save
     * @return the saved document with updatedAt set
     */
    public FirestoreUserPermissions saveBlocking(FirestoreUserPermissions userPermissions) {
        if (userPermissions == null) {
            throw new IllegalArgumentException("userPermissions must not be null");
        }
        if (userPermissions.getFirebaseUid() == null
                || userPermissions.getFirebaseUid().isBlank()) {
            throw new IllegalArgumentException(
                    "userPermissions.firebaseUid must not be null or blank");
        }

        try {
            userPermissions.setUpdatedAt(clock.instant());

            firestore
                    .collection(COLLECTION)
                    .document(userPermissions.getFirebaseUid())
                    .set(userPermissions) // full replace — NOT merge
                    .get();

            log.info("Saved user_permissions for uid: {}", userPermissions.getFirebaseUid());
            return userPermissions;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while saving user_permissions for uid: {}",
                    userPermissions.getFirebaseUid(), e);
            throw new RuntimeException(
                    "Firestore write interrupted for uid: " + userPermissions.getFirebaseUid(), e);

        } catch (Exception e) {
            log.error("Failed to save user_permissions for uid {}: {}",
                    userPermissions.getFirebaseUid(), e.getMessage(), e);
            throw new RuntimeException(
                    "Firestore write failed for uid: " + userPermissions.getFirebaseUid(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Default document creation
    // -------------------------------------------------------------------------

    /**
     * Creates and saves a default USER document for a newly registered user,
     * reactively.
     *
     * Called by the registration flow on first user creation. Starts the user
     * with the USER role and no overrides.
     *
     * Uses the injected Clock for the updatedAt timestamp — testable without
     * mocking Instant.now().
     *
     * @param firebaseUid Firebase Auth UID of the new user
     * @return Mono emitting the created document
     */
    public Mono<FirestoreUserPermissions> createDefault(String firebaseUid) {
        FirestoreUserPermissions defaultPerms =
                FirestoreUserPermissions.defaultFor(firebaseUid, clock);
        return save(defaultPerms)
                .doOnSuccess(saved ->
                        log.info("Created default user_permissions for uid: {}", firebaseUid));
    }

    /**
     * Creates and saves a default USER document, blocking variant.
     *
     * @param firebaseUid Firebase Auth UID of the new user
     * @return the created document
     */
    public FirestoreUserPermissions createDefaultBlocking(String firebaseUid) {
        FirestoreUserPermissions defaultPerms =
                FirestoreUserPermissions.defaultFor(firebaseUid, clock);
        return saveBlocking(defaultPerms);
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    /**
     * Deletes a user's permission document, reactively.
     *
     * @param firebaseUid Firebase Auth UID
     * @return Mono completing when deletion is done
     */
    public Mono<Void> delete(String firebaseUid) {
        if (firebaseUid == null || firebaseUid.isBlank()) {
            return Mono.error(new IllegalArgumentException(
                    "firebaseUid must not be null or blank"));
        }

        return Mono.fromCallable(() -> {
                    firestore
                            .collection(COLLECTION)
                            .document(firebaseUid)
                            .delete()
                            .get(); // blocking — safe on boundedElastic
                    return firebaseUid;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(uid ->
                        log.info("Deleted user_permissions for uid: {}", uid))
                .doOnError(e -> log.error(
                        "Failed to delete user_permissions for uid {}: {}",
                        firebaseUid, e.getMessage(), e))
                .onErrorMap(e -> new RuntimeException(
                        "Firestore delete failed for uid: " + firebaseUid, e))
                .then();
    }

    /**
     * Blocking variant of delete.
     *
     * @param firebaseUid Firebase Auth UID
     */
    public void deleteBlocking(String firebaseUid) {
        if (firebaseUid == null || firebaseUid.isBlank()) {
            throw new IllegalArgumentException("firebaseUid must not be null or blank");
        }

        try {
            firestore
                    .collection(COLLECTION)
                    .document(firebaseUid)
                    .delete()
                    .get();

            log.info("Deleted user_permissions for uid: {}", firebaseUid);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Interrupted while deleting user_permissions for uid: {}", firebaseUid, e);
            throw new RuntimeException(
                    "Firestore delete interrupted for uid: " + firebaseUid, e);

        } catch (Exception e) {
            log.error("Failed to delete user_permissions for uid {}: {}",
                    firebaseUid, e.getMessage(), e);
            throw new RuntimeException(
                    "Firestore delete failed for uid: " + firebaseUid, e);
        }
    }
}