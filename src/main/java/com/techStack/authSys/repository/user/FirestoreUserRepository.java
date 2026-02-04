package com.techStack.authSys.repository.user;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.techStack.authSys.constants.SecurityConstants;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.data.DataMappingException;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.user.*;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.util.firebase.FirestoreUserMapper;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.net.SocketException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Repository for Firestore User Operations
 *
 * Responsibilities:
 * - All Firestore CRUD operations
 * - Query execution
 * - Document mapping
 * - Transaction management
 */
@Repository
public class FirestoreUserRepository {

    private static final Logger logger = LoggerFactory.getLogger(FirestoreUserRepository.class);

    private final Firestore firestore;
    private final RedisUserCacheService cacheService;

    public FirestoreUserRepository(Firestore firestore, RedisUserCacheService cacheService) {
        this.firestore = firestore;
        this.cacheService = cacheService;
    }

    // ============================================================================
    // ATOMIC SAVE OPERATIONS
    // ============================================================================

    /**
     * Saves user with profile, password history, and permissions atomically
     * Used during initial user creation with full data setup
     */
    public Mono<User> saveUserAtomic(User user, String ipAddress, String deviceFingerprint, PermissionData permData) {
        return Mono.defer(() -> {
            try {
                Map<String, Object> userData = FirestoreUserMapper.userToMap(user);
                ensureTimestamps(userData);

                UserProfile profile = buildUserProfile(user);
                UserPasswordHistory passwordHistory = buildPasswordHistory(user, ipAddress, deviceFingerprint);
                Map<String, Object> permissionsDoc = buildPermissionsDocument(user, permData);

                return executeBatchWrite(user, userData, profile, passwordHistory, permissionsDoc)
                        .thenReturn(user);
            } catch (Exception e) {
                logger.error("❌ Error preparing user data: {}", e.getMessage(), e);
                return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to prepare user data"));
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Save user with permissions (for approval workflow)
     * Used when approving existing users - updates user doc + permissions doc
     */
    public Mono<User> saveUserWithPermissions(User user, PermissionData permData) {
        return Mono.defer(() -> {
            try {
                logger.info("💾 Saving user with permissions: {}", user.getEmail());

                Map<String, Object> userData = FirestoreUserMapper.userToMap(user);
                ensureTimestamps(userData);

                Map<String, Object> permissionsDoc = buildPermissionsDocument(user, permData);

                return executeSaveWithPermissions(user, userData, permissionsDoc)
                        .thenReturn(user)
                        .doOnSuccess(savedUser ->
                                logger.info("✅ User saved with permissions: {}", savedUser.getEmail()))
                        .doOnError(e ->
                                logger.error("❌ Failed to save user with permissions: {}", e.getMessage()));
            } catch (Exception e) {
                logger.error("❌ Error preparing user/permission data: {}", e.getMessage(), e);
                return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to prepare user data for save"));
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Execute batch write for user + permissions (approval workflow)
     */
    private Mono<Void> executeSaveWithPermissions(
            User user,
            Map<String, Object> userData,
            Map<String, Object> permissionsDoc) {

        WriteBatch batch = firestore.batch();

        // Update/create user document
        DocumentReference userRef = firestore.collection(SecurityConstants.COLLECTION_USERS)
                .document(user.getId());

        // Update/create permissions document
        DocumentReference permissionsRef = userRef
                .collection(SecurityConstants.COLLECTION_USER_PERMISSIONS)
                .document(SecurityConstants.ACTIVE_PERMISSIONS_DOC_ID);

        batch.set(userRef, userData);
        batch.set(permissionsRef, permissionsDoc);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(batch.commit()))
                .doOnSuccess(result -> logger.info("✅ Batch save successful for user {}", user.getEmail()))
                .doOnError(error -> logger.error("❌ Batch save failed for {}: {}", user.getId(), error.getMessage()))
                .retryWhen(Retry.backoff(3, Duration.ofMillis(100)))
                .then();
    }

    /**
     * Execute atomic Firestore batch write (full user creation)
     */
    private Mono<Void> executeBatchWrite(
            User user,
            Map<String, Object> userData,
            UserProfile profile,
            UserPasswordHistory passwordHistory,
            Map<String, Object> permissionsDoc) {

        WriteBatch batch = firestore.batch();

        DocumentReference userRef = firestore.collection(SecurityConstants.COLLECTION_USERS)
                .document(user.getId());
        DocumentReference profileRef = userRef.collection(SecurityConstants.COLLECTION_USER_PROFILES)
                .document(SecurityConstants.PROFILE_DOC_ID);
        DocumentReference passwordHistoryRef = userRef.collection(SecurityConstants.COLLECTION_USER_PASSWORD_HISTORY)
                .document();
        DocumentReference permissionsRef = userRef.collection(SecurityConstants.COLLECTION_USER_PERMISSIONS)
                .document(SecurityConstants.ACTIVE_PERMISSIONS_DOC_ID);

        batch.set(userRef, userData);
        batch.set(profileRef, profile);
        batch.set(passwordHistoryRef, passwordHistory);
        batch.set(permissionsRef, permissionsDoc);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(batch.commit()))
                .doOnSuccess(result -> logger.info("✅ Atomic save successful for user {}", user.getEmail()))
                .doOnError(error -> logger.error("❌ Atomic save failed for {}: {}", user.getId(), error.getMessage()))
                .retryWhen(Retry.backoff(3, Duration.ofMillis(100)))
                .then();
    }

    // ============================================================================
    // PERMISSION OPERATIONS
    // ============================================================================

    /**
     * Get user permissions document
     */
    public Mono<Map<String, Object>> getUserPermissions(String userId) {
        DocumentReference permissionsRef = firestore.collection(SecurityConstants.COLLECTION_USERS)
                .document(userId)
                .collection(SecurityConstants.COLLECTION_USER_PERMISSIONS)
                .document(SecurityConstants.ACTIVE_PERMISSIONS_DOC_ID);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(permissionsRef.get()))
                .map(documentSnapshot -> {
                    if (!documentSnapshot.exists()) {
                        throw new CustomException(HttpStatus.NOT_FOUND,
                                "Permissions not found for user: " + userId);
                    }
                    return documentSnapshot.getData();
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Update user permissions only
     */
    public Mono<Void> updateUserPermissions(String userId, PermissionData permData) {
        return Mono.defer(() -> {
            Map<String, Object> permissionsDoc = Map.of(
                    "userId", userId,
                    "roles", permData.getRoles(),
                    "permissions", permData.getPermissions(),
                    "status", permData.getStatus().name(),
                    "approvedBy", permData.getApprovedBy() != null ? permData.getApprovedBy() : "",
                    "approvedAt", permData.getApprovedAt() != null ? permData.getApprovedAt() : Instant.now(),
                    "updatedAt", Instant.now()
            );

            DocumentReference permissionsRef = firestore.collection(SecurityConstants.COLLECTION_USERS)
                    .document(userId)
                    .collection(SecurityConstants.COLLECTION_USER_PERMISSIONS)
                    .document(SecurityConstants.ACTIVE_PERMISSIONS_DOC_ID);

            ApiFuture<WriteResult> future = permissionsRef.set(permissionsDoc);

            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .doOnSuccess(result -> logger.info("✅ Permissions updated for user {}", userId))
                    .doOnError(error -> logger.error("❌ Failed to update permissions: {}", error.getMessage()))
                    .then();
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ============================================================================
    // FIND OPERATIONS
    // ============================================================================

    public Mono<User> findById(String userId) {
        DocumentReference userRef = firestore.collection(SecurityConstants.COLLECTION_USERS).document(userId);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(userRef.get()))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(snapshot -> {
                    if (!snapshot.exists()) {
                        return Mono.error(new UserNotFoundException("User not found: " + userId));
                    }

                    User user = FirestoreUserMapper.documentToUser(snapshot);
                    if (user == null) {
                        return Mono.error(new DataMappingException("Failed to map user document"));
                    }

                    return Mono.just(user);
                });
    }

    public Mono<User> findByEmail(String email) {
        return Mono.fromCallable(() -> firestore.collection(SecurityConstants.COLLECTION_USERS)
                        .whereEqualTo("email", email)
                        .limit(1)
                        .get())
                .flatMap(future -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(future)))
                .subscribeOn(Schedulers.boundedElastic())
                .retryWhen(Retry.backoff(3, Duration.ofMillis(300))
                        .filter(e -> e instanceof SocketException))
                .flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        return Mono.error(new UserNotFoundException("User not found: " + email));
                    }

                    DocumentSnapshot doc = querySnapshot.getDocuments().get(0);
                    User user = FirestoreUserMapper.documentToUser(doc);

                    if (user == null) {
                        return Mono.error(new DataMappingException("Failed to map user document"));
                    }

                    return Mono.just(user);
                });
    }

    public Mono<User> fetchUserWithPermissions(String userId) {
        return Mono.fromCallable(() -> {
                    // Fetch user document
                    DocumentSnapshot userDoc = firestore.collection(SecurityConstants.COLLECTION_USERS)
                            .document(userId).get().get();

                    if (!userDoc.exists()) {
                        throw new UserNotFoundException("User not found: " + userId);
                    }

                    User user = FirestoreUserMapper.documentToUser(userDoc);
                    if (user == null) {
                        throw new DataMappingException("Failed to deserialize user");
                    }

                    // Fetch permissions
                    DocumentSnapshot permDoc = firestore.collection(SecurityConstants.COLLECTION_USERS)
                            .document(userId)
                            .collection(SecurityConstants.COLLECTION_USER_PERMISSIONS)
                            .document(SecurityConstants.ACTIVE_PERMISSIONS_DOC_ID)
                            .get().get();

                    if (permDoc.exists()) {
                        List<String> roles = (List<String>) permDoc.get("roles");
                        List<String> permissions = (List<String>) permDoc.get("permissions");

                        if (roles != null) user.setRoleNames(roles);
                        if (permissions != null) user.setAdditionalPermissions(permissions);
                    }

                    return user;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(user -> cacheService.cacheUserWithRolesAndPermissions(user).thenReturn(user));
    }

    public Flux<User> findByStatus(UserStatus status) {
        return Mono.fromCallable(() -> firestore.collection(SecurityConstants.COLLECTION_USERS)
                        .whereEqualTo("status", status.name())
                        .get())
                .flatMap(future -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(future)))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        return Flux.empty();
                    }

                    return Flux.fromIterable(querySnapshot.getDocuments())
                            .map(FirestoreUserMapper::documentToUser)
                            .filter(Objects::nonNull);
                });
    }

    public Flux<User> findAll() {
        return Flux.defer(() -> {
            CollectionReference usersCollection = firestore.collection(SecurityConstants.COLLECTION_USERS);
            ApiFuture<QuerySnapshot> future = usersCollection.get();

            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .flatMapMany(querySnapshot -> {
                        if (querySnapshot.isEmpty()) {
                            return Flux.empty();
                        }

                        return Flux.fromIterable(querySnapshot.getDocuments())
                                .mapNotNull(FirestoreUserMapper::documentToUser);
                    });
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Boolean> existsByEmail(String email) {
        return Mono.fromCallable(() -> firestore.collection(SecurityConstants.COLLECTION_USERS)
                        .whereEqualTo("email", email)
                        .limit(1)
                        .get())
                .flatMap(future -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(future)))
                .map(snapshot -> !snapshot.isEmpty())
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ============================================================================
    // UPDATE OPERATIONS
    // ============================================================================

    public Mono<User> save(User user) {
        return Mono.defer(() -> {
            Map<String, Object> userData = buildUserUpdateMap(user);

            DocumentReference userRef = firestore.collection(SecurityConstants.COLLECTION_USERS)
                    .document(user.getId());
            ApiFuture<WriteResult> future = userRef.update(userData);

            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .doOnSuccess(result -> logger.info("✅ User updated: {} at {}",
                            user.getId(), result.getUpdateTime()))
                    .doOnError(error -> logger.error("❌ Update failed for {}: {}",
                            user.getId(), error.getMessage()))
                    .thenReturn(user);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Void> update(User user) {
        return save(user).then();
    }

    public Mono<Void> updateLastLogin(String userId, String ipAddress) {
        Instant now = Instant.now();

        Map<String, Object> updates = Map.of(
                "lastLogin", Timestamp.of(Date.from(now)),
                "lastLoginTimestamp", Timestamp.of(Date.from(now)),
                "lastLoginIp", ipAddress,
                "lastLoginIpAddress", ipAddress
        );

        ApiFuture<WriteResult> future = firestore.collection(SecurityConstants.COLLECTION_USERS)
                .document(userId).update(updates);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                .doOnSuccess(ignored -> logger.info("✅ Updated last login for {}", userId))
                .doOnError(e -> logger.error("❌ Error updating last login: {}", e.getMessage()))
                .then();
    }

    // ============================================================================
    // DELETE OPERATIONS
    // ============================================================================

    public Mono<Void> delete(String userId) {
        return Mono.defer(() -> {
            DocumentReference userRef = firestore.collection(SecurityConstants.COLLECTION_USERS)
                    .document(userId);
            ApiFuture<WriteResult> future = userRef.delete();

            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .doOnSuccess(result -> logger.info("✅ Deleted user from Firestore: {}", userId))
                    .doOnError(error -> logger.error("❌ Failed to delete user: {}", userId))
                    .then();
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ============================================================================
    // GENERIC DOCUMENT OPERATIONS
    // ============================================================================

    public Mono<Map<String, Object>> getDocument(String collection, String documentId) {
        return Mono.fromCallable(() -> {
                    DocumentReference docRef = firestore.collection(collection).document(documentId);
                    DocumentSnapshot document = docRef.get().get();
                    return document.exists() ? document.getData() : null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> Mono.empty());
    }

    public Mono<Void> setDocument(String collection, String documentId, Map<String, Object> data) {
        return Mono.fromCallable(() -> {
                    DocumentReference docRef = firestore.collection(collection).document(documentId);
                    docRef.set(data).get();
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    public Mono<Void> deleteDocument(String collection, String documentId) {
        logger.warn("🗑️ Deleting document: {}/{}", collection, documentId);

        DocumentReference docRef = firestore.collection(collection).document(documentId);
        ApiFuture<WriteResult> future = docRef.delete();

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(result -> logger.info("✅ Deleted: {}/{}", collection, documentId))
                .doOnError(error -> logger.error("❌ Delete failed: {}", error.getMessage()))
                .then();
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private void ensureTimestamps(Map<String, Object> userData) {
        if (userData.get("createdAt") == null) {
            userData.put("createdAt", Timestamp.now());
        }
        if (userData.get("updatedAt") == null) {
            userData.put("updatedAt", Timestamp.now());
        }
    }

    private UserProfile buildUserProfile(User user) {
        return UserProfile.builder()
                .userId(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .profilePictureUrl(user.getProfilePictureUrl() != null ? user.getProfilePictureUrl() : "")
                .bio(user.getBio() != null ? user.getBio() : "")
                .isPublic(true)
                .build();
    }

    private UserPasswordHistory buildPasswordHistory(User user, String ipAddress, String deviceFingerprint) {
        return UserPasswordHistory.builder()
                .userId(user.getId())
                .createdAt(Instant.now())
                .changedFromIp(ipAddress)
                .changedByUserAgent(deviceFingerprint)
                .build();
    }

    private Map<String, Object> buildPermissionsDocument(User user, PermissionData permData) {
        Map<String, Object> doc = new HashMap<>();
        doc.put("userId", user.getId());
        doc.put("email", user.getEmail());
        doc.put("roles", permData.getRoles());
        doc.put("permissions", permData.getPermissions());
        doc.put("status", permData.getStatus().name());
        doc.put("createdAt", Instant.now());
        doc.put("updatedAt", Instant.now());
        doc.put("approvedBy", permData.getApprovedBy());
        doc.put("approvedAt", permData.getApprovedAt());
        return doc;
    }

    private Map<String, Object> buildUserUpdateMap(User user) {
        Map<String, Object> data = new HashMap<>();
        data.put("firstName", user.getFirstName());
        data.put("lastName", user.getLastName());
        data.put("phoneNumber", user.getPhoneNumber());
        data.put("department", user.getDepartment());
        data.put("status", user.getStatus().name());
        data.put("enabled", user.isEnabled());
        data.put("accountLocked", user.isAccountLocked());
        data.put("forcePasswordChange", user.isForcePasswordChange());
        data.put("roleNames", user.getRoleNames());
        data.put("additionalPermissions", user.getAdditionalPermissions() != null ?
                user.getAdditionalPermissions() : Collections.emptyList());
        data.put("updatedAt", Instant.now());
        return data;
    }
}