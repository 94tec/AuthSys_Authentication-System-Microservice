package com.techStack.authSys.service;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.database.GenericTypeIndicator;
import com.techStack.authSys.config.FirebaseConfig;
import com.techStack.authSys.dto.PendingUserResponse;
import com.techStack.authSys.dto.RequesterContext;
import com.techStack.authSys.dto.SecurityContext;
import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.exception.*;
import com.techStack.authSys.models.*;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.repository.PermissionProvider;
import com.techStack.authSys.util.FirestoreUserMapper;
import com.techStack.authSys.util.FirestoreUtil;
import io.jsonwebtoken.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;


import java.net.SocketException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Component
public class FirebaseServiceAuth {

    private static final Logger logger = LoggerFactory.getLogger(FirebaseServiceAuth.class);

    private static final String COLLECTION_USERS = "users";
    private static final String COLLECTION_USER_PROFILES = "user_profiles";
    private static final String COLLECTION_USER_PASSWORD_HISTORY = "user_password_history";
    private static final String COLLECTION_USER_PERMISSIONS = "user_permissions";

    // Injected dependencies
    private final Firestore firestore;
    private final EncryptionService encryptionService;
    private final FirebaseAuth firebaseAuth;
    private final DeviceVerificationService deviceVerificationService;
    private final FirebaseConfig firebaseConfig;
    private final MetricsService metricsService;
    private final RedisUserCacheService redisCacheService;
    private final RoleAssignmentService roleAssignmentService;
    private final PermissionProvider permissionProvider;

    @Autowired
    public FirebaseServiceAuth(Firestore firestore,
                               EncryptionService encryptionService,
                               FirebaseAuth firebaseAuth,
                               DeviceVerificationService deviceVerificationService,
                               FirebaseConfig firebaseConfig,
                               MetricsService metricsService,
                               RedisUserCacheService redisCacheService,
                               @Lazy  RoleAssignmentService roleAssignmentService,
                               PermissionProvider permissionProvider) {
        this.firestore = firestore;
        this.encryptionService = encryptionService;
        this.firebaseAuth = firebaseAuth;
        this.deviceVerificationService = deviceVerificationService;
        this.firebaseConfig = firebaseConfig;
        this.metricsService = metricsService;
        this.redisCacheService = redisCacheService;
        this.roleAssignmentService = roleAssignmentService;
        this.permissionProvider = permissionProvider;
    }
    public Mono<User> createSuperAdmin(User user, String password) {
        UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                .setEmail(user.getEmail())
                .setEmailVerified(user.isEmailVerified())
                .setPassword(password)
                .setPhoneNumber(user.getPhoneNumber());

        return Mono.fromCallable(() -> firebaseAuth.createUser(request))
                .map(userRecord -> mapFirebaseUserToDomain(userRecord, user));
    }

    private User mapFirebaseUserToDomain(UserRecord userRecord, User baseUser) {
        final Instant now = Instant.now(); // Single time source

        baseUser.setId(userRecord.getUid());
        baseUser.setCreatedAt(now);
        baseUser.setUpdatedAt(now);
        return baseUser;
    }
    public Mono<User> createFirebaseUser(UserDTO userDto, String ipAddress, String deviceFingerprint) {
        return createFirebaseAuthUser(userDto)     // ✅ Create Firebase user in boundedElastic
                .flatMap(userRecord -> encryptPassword(userDto.getPassword())
                        .map(enc -> buildLocalUserModel(userRecord, userDto, enc, deviceFingerprint)))
                .flatMap(user ->
                        saveUserToFirestore(user, ipAddress)
                                .then(deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint))
                                .thenReturn(user)
                )
                .onErrorResume(e -> rollbackFirebaseUserCreation(userDto.getEmail())
                        .then(Mono.error(e)));
    }
    private Mono<UserRecord> createFirebaseAuthUser(UserDTO userDto) {
        return Mono.fromCallable(() -> {
            UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                    .setEmail(userDto.getEmail())
                    .setPassword(userDto.getPassword())
                    .setEmailVerified(false)
                    .setDisabled(false);

            if (userDto.getPhoneNumber() != null) request.setPhoneNumber(userDto.getPhoneNumber());
            if (userDto.getFirstName() != null && userDto.getLastName() != null)
                request.setDisplayName(userDto.getFirstName() + " " + userDto.getLastName());

            return firebaseAuth.createUser(request);
        }).subscribeOn(Schedulers.boundedElastic());
    }
    private Mono<String> encryptPassword(String password) {
        return Mono.fromCallable(() -> encryptionService.encrypt(password))
                .subscribeOn(Schedulers.boundedElastic());
    }
    private User buildLocalUserModel(UserRecord userRecord, UserDTO userDto, String encryptedPassword,
                                     String deviceFingerprint) {

        List<String> roleNames = userDto.getRoles().stream()
                .map(role -> Roles.fromName(role)
                        .orElseThrow(() -> new IllegalArgumentException("Invalid role: " + role)))
                .map(Roles::name)
                .collect(Collectors.toList());

        return User.builder()
                .id(userRecord.getUid())
                .firstName(userDto.getFirstName())
                .lastName(userDto.getLastName())
                .email(userDto.getEmail())
                .username(userDto.getUsername())
                .identityNo(userDto.getIdentityNo())
                .phoneNumber(userDto.getPhoneNumber())
                .roleNames(roleNames)
                .enabled(false)                                   // ✅ role service updates
                .emailVerified(false)
                .accountLocked(false)
                .password(encryptedPassword)
                .lastPasswordChangeDate(LocalDate.now().toString())
                .deviceFingerprint(deviceFingerprint)
                .status(User.Status.PENDING_APPROVAL)            // ✅ updated by role service
                .permissions(new ArrayList<>())                  // ✅ safe initialization
                .build();
    }

    public Mono<User> saveUser(User user, String ipAddress, String deviceFingerprint) {
        return saveUserToFirestore(user, ipAddress)
                .then(deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint))
                .thenReturn(user);
    }

    private Mono<User> saveUserToFirestore(User user, String ipAddress) {
        return Mono.defer(() -> {
            try {
                // Use the reverse mapper for consistency
                Map<String, Object> userData = FirestoreUserMapper.userToMap(user);

                // Ensure timestamps are set
                if (userData.get("createdAt") == null) {
                    userData.put("createdAt", Timestamp.now());
                }

                // Build UserProfile
                UserProfile userProfile = UserProfile.builder()
                        .userId(user.getId())
                        .firstName(user.getFirstName())
                        .lastName(user.getLastName())
                        .profilePictureUrl(user.getProfilePictureUrl() != null ? user.getProfilePictureUrl() : "")
                        .bio(user.getBio() != null ? user.getBio() : "")
                        .isPublic(true)
                        .build();

                // Build Password History
                UserPasswordHistory userPasswordHistory = UserPasswordHistory.builder()
                        .userId(user.getId())
                        .createdAt(Instant.now())
                        .changedByIp(ipAddress)
                        .changedByUserAgent(user.getDeviceFingerprint())
                        .build();

                // Batch write
                WriteBatch batch = firestore.batch();
                DocumentReference userRef = firestore.collection(COLLECTION_USERS).document(user.getId());
                DocumentReference profileRef = firestore
                        .collection(COLLECTION_USERS)
                        .document(user.getId())
                        .collection(COLLECTION_USER_PROFILES)
                        .document();
                DocumentReference passwordHistoryRef = firestore
                        .collection(COLLECTION_USERS)
                        .document(user.getId())
                        .collection(COLLECTION_USER_PASSWORD_HISTORY)
                        .document();

                batch.set(userRef, userData);
                batch.set(profileRef, userProfile);
                batch.set(passwordHistoryRef, userPasswordHistory);

                return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(batch.commit()))
                        .doOnSuccess(result -> {
                            logger.info("✅ Firestore batch write successful for user {}", user.getId());
                            logger.info("✅ User status: {}", user.getStatus());
                        })
                        .doOnError(error -> logger.error("❌ Firestore batch write failed for user {}: {}",
                                user.getId(), error.getMessage()))
                        .retryWhen(Retry.backoff(3, Duration.ofMillis(100)))
                        .thenReturn(user)
                        .subscribeOn(Schedulers.boundedElastic());

            } catch (Exception e) {
                logger.error("❌ Error preparing Firestore data for user {}: {}", user.getEmail(), e.getMessage(), e);
                return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to prepare user data"));
            }
        });
    }

    public Mono<Void> saveUserPermissions(User user) {
        return Mono.defer(() -> {
            try {
                boolean isPrivileged = user.getRoleNames().stream()
                        .anyMatch(role -> role.equalsIgnoreCase("ADMIN") ||
                                role.equalsIgnoreCase("SUPER_ADMIN") ||
                                role.equalsIgnoreCase("MANAGER"));

                Map<String, Object> UserPermissions = new HashMap<>();

                if (isPrivileged) {
                    // Privileged users: Full permissions immediately
                    // Resolve actual permissions from roles
                    Set<String> resolvedPermissions = permissionProvider.resolveEffectivePermission(user);
                    List<String> permissionsList = new ArrayList<>(resolvedPermissions);
                    List<String> roleList = new ArrayList<>(user.getRoleNames());

                    // Validate we actually got permissions
                    if (permissionsList.isEmpty()) {
                        logger.error("❌ No permissions resolved for privileged user: {}", user.getEmail());
                        logger.error("❌ Roles: {}", user.getRoleNames());
                        return Mono.error(new RuntimeException("Failed to resolve permissions"));
                    }
                        UserPermissions.put("userId", user.getId());
                        UserPermissions.put("email", user.getEmail());
                        UserPermissions.put("roles", roleList);
                        UserPermissions.put("permissions", permissionsList);
                        UserPermissions.put("status", User.Status.ACTIVE.name());
                        UserPermissions.put("approvedBy", user.getCreatedBy() != null ? user.getCreatedBy() : "SYSTEM");
                        UserPermissions.put("approvedAt", Instant.now());
                        UserPermissions.put("createdAt", Instant.now());

                        logger.info("✅ Saving {} permissions for privileged user: {}", permissionsList.size(), user.getEmail());
                        logger.debug("📋 Permissions: {}", permissionsList);
                } else {
                    // Regular users: Empty permissions, pending approval
                    UserPermissions.put("userId", user.getId());
                    UserPermissions.put("email", user.getEmail());
                    UserPermissions.put("roles", Collections.emptyList());
                    UserPermissions.put("permissions", Collections.emptyList());
                    UserPermissions.put("status", User.Status.PENDING_APPROVAL.name());
                    UserPermissions.put("approvedBy", null);
                    UserPermissions.put("approvedAt", null);
                    UserPermissions.put("createdAt", Instant.now());

                    //logger.info("⚠️ Creating PENDING_APPROVAL permissions for user: {}", user.getEmail());
                    logger.info("⚠️ Creating PENDING_APPROVAL permissions for user: {}. Awaiting manager approval.", user.getEmail());

                }

                return savePermissionsToFirestore(user, UserPermissions);

            } catch (Exception e) {
                logger.error("❌ Error preparing permissions for user {}: {}", user.getEmail(), e.getMessage(), e);
                return Mono.error(new RuntimeException("Failed to prepare permissions", e));
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Void> savePermissionsToFirestore(User user, Map<String, Object> UserPermissions) {
        DocumentReference docRef = firestore
                .collection(COLLECTION_USERS)
                .document(user.getId())
                .collection(COLLECTION_USER_PERMISSIONS)
                .document("active_permissions"); // Fixed document name

        ApiFuture<WriteResult> apiFuture = docRef.set(UserPermissions);
        CompletableFuture<WriteResult> javaFuture = FirestoreUtil.toCompletableFuture(apiFuture);

        return Mono.fromFuture(() -> javaFuture)
                .doOnSuccess(result ->
                        logger.info("✅ Permissions saved for {} with status {} at {}",
                                user.getEmail(), UserPermissions.get("status"), result.getUpdateTime()))
                .doOnError(error ->
                        logger.error("❌ Failed to save permissions for {}: {}",
                                user.getEmail(), error.getMessage(), error))
                .then();
    }

    private Mono<Void> saveToFirestore(User user, UserPermissions document) {
        DocumentReference docRef = firestore
                .collection(COLLECTION_USERS)
                .document(user.getId())
                .collection(COLLECTION_USER_PERMISSIONS)
                .document();

        ApiFuture<WriteResult> apiFuture = docRef.set(document);
        CompletableFuture<WriteResult> javaFuture = FirestoreUtil.toCompletableFuture(apiFuture);

        return Mono.fromFuture(() -> javaFuture)
                .doOnSuccess(result ->
                        logger.info("✅ Saved user permissions for {} at {}", user.getEmail(), result.getUpdateTime()))
                .doOnError(error ->
                        logger.error("❌ Failed to save permissions for {}: {}", user.getEmail(), error.getMessage(), error))
                .then();
    }

    public Mono<Void> validateCredentials(String email, String password) {
        return getUserRecord(email)
                .flatMap(userRecord -> signInWithFirebase(email, password))
                .onErrorMap(this::translateFirebaseException);
    }
    // Fetch user record from Firebase
    private Mono<UserRecord> getUserRecord(String email) {
        return Mono.fromFuture(
                FirestoreUtil.toCompletableFuture(
                        FirebaseAuth.getInstance().getUserByEmailAsync(email)
                )
        ).onErrorResume(e -> Mono.error(new AuthenticationException("User not found")));
    }
    //Purpose: To determine if an email address is already registered in the Firebase Authentication system.
    //Best Used For: Registration flow (to prevent duplicate accounts) or checking availability.
    public Mono<Boolean> checkEmailAvailability(String email) {
        return Mono.defer(() -> {
            try {
                // The blocking call that needs offloading
                FirebaseAuth.getInstance().getUserByEmail(email);
                // User exists
                return Mono.just(true);
            } catch (FirebaseAuthException e) {
                if ("USER_NOT_FOUND".equals(e.getAuthErrorCode().name())) {
                    // Email is available
                    return Mono.just(false);
                }
                // Propagate unexpected Firebase errors
                return Mono.error(new CustomException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Firebase authentication error: " + e.getMessage()
                ));
            }
            // ⭐ FIX: Offload the blocking call to a dedicated thread pool
        }).subscribeOn(Schedulers.boundedElastic());
    }
    public Mono<Void> signInWithFirebase(String email, String password) {
        String firebaseAuthUrl = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" + firebaseConfig.getFirebaseApiKey();

        return WebClient.create()
                .post()
                .uri(firebaseAuthUrl)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)  // Add correct header
                .bodyValue(Map.of(
                        "email", email,
                        "password", password,
                        "returnSecureToken", true
                ))
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, response ->
                        response.bodyToMono(Map.class).flatMap(errorBody -> {
                            logger.warn("🔐 Firebase REST error during sign-in for {}: {}", email, errorBody);

                            String errorCode = extractFirebaseRestErrorCode(errorBody);
                            return Mono.error(new FirebaseRestAuthException(errorCode, "Firebase REST auth failure"));
                        })
                )
                .bodyToMono(Map.class)
                .doOnSuccess(response -> {
                    if (response != null && response.containsKey("idToken")) {
                        logger.info("User \uD83D\uDD13 {} authenticated successfully. Firebase UID: {}",
                                email, response.get("localId"));
                    } else {
                        logger.warn("Unexpected Firebase response for {}: {}", email, response);
                    }
                })
                .flatMap(response -> Mono.empty()) // Continue on success
                .transform(this::handleAuthErrors).then();
    }
    //Purpose: To retrieve the raw UserRecord object from the Firebase Authentication system.
    //Best Used For: Authentication/Authorization checks, fetching basic user ID (UID), or triggering Firebase-specific actions (like password reset).
    public Mono<UserRecord> getUserByEmail(String email) {
        return Mono.fromCallable(() -> FirebaseAuth.getInstance().getUserByEmail(email))
                .subscribeOn(Schedulers.boundedElastic()) // Run blocking call off the main thread
                .retryWhen(Retry.backoff(3, Duration.ofMillis(300))
                        .filter(e -> e instanceof SocketException || e instanceof IOException)
                        .onRetryExhaustedThrow((retrySpec, signal) ->
                                new AuthException("🔥 Firebase user fetch retries exhausted", signal.failure(), HttpStatus.SERVICE_UNAVAILABLE))
                )
                .onErrorResume(e -> {
                    logger.warn("❌ Error fetching user by email '{}': {}", email, e.getMessage());

                    if (e instanceof FirebaseAuthException firebaseEx) {
                        return Mono.error(firebaseEx);
                    }

                    return Mono.error(new AuthException("❌ Unexpected error during user lookup", e, HttpStatus.INTERNAL_SERVER_ERROR));
                });
    }

    public Mono<User> fetchUserDetailsWithPermissions(String userId) {
        return Mono.fromCallable(() -> {
                    logger.info("🔍 Fetching user details and permissions for userId: {}", userId);

                    DocumentSnapshot userDoc = firestore.collection(COLLECTION_USERS).document(userId).get().get();
                    if (!userDoc.exists()) {
                        throw new CustomException(HttpStatus.NOT_FOUND, "User not found");
                    }

                    //User user = userDoc.toObject(User.class);
                    User user = FirestoreUserMapper.documentToUser(userDoc);
                    //User user = FirestoreUserMapper.mapToUser(userDoc.getData());
                    if (user == null) {
                        logger.error("❗ Failed to deserialize user for userId: {}", userId);
                        throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to deserialize user");
                    }

                    // ✅ Use GenericTypeIndicator to safely parse lists
                    GenericTypeIndicator<List<String>> listType = new GenericTypeIndicator<>() {};
                    List<QueryDocumentSnapshot> permissionDocs = firestore
                            .collection(COLLECTION_USERS)
                            .document(userId)
                            .collection(COLLECTION_USER_PERMISSIONS)
                            .get()
                            .get()
                            .getDocuments();

                    List<String> roles = new ArrayList<>();
                    List<String> permissions = new ArrayList<>();

                    for (QueryDocumentSnapshot doc : permissionDocs) {
                        @SuppressWarnings("unchecked")
                        List<String> docRoles = (List<String>) doc.get("roles");

                        @SuppressWarnings("unchecked")
                        List<String> docPermissions = (List<String>) doc.get("permissions");

                        if (docRoles != null) roles.addAll(docRoles);
                        if (docPermissions != null) permissions.addAll(docPermissions);
                    }
                    user.setRoleNames(roles);
                    user.setPermissions(permissions);

                    return user;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(user -> {
                    Set<Roles> roles = new HashSet<>(user.getRoles());
                    Set<Permissions> perms = user.getPermissions().stream()
                            .map(Permissions::valueOf)
                            .collect(Collectors.toSet());

                    logger.info("📦 Caching user data for userId: {}", userId);
                    return redisCacheService.cacheAllUserData(user, roles, perms)
                            .thenReturn(user);
                });
    }

    private String extractFirebaseRestErrorCode(Map<?, ?> errorBody) {
        try {
            Map<?, ?> error = (Map<?, ?>) errorBody.get("error");
            return (String) ((Map<?, ?>) ((List<?>) error.get("errors")).get(0)).get("message");
        } catch (Exception e) {
            logger.error("⚠️ Failed to extract Firebase error code: {}", e.getMessage());
            return "unknown";
        }
    }

    // Translate Firebase errors to meaningful exceptions
    public Throwable translateFirebaseException(Throwable e) {
        // Unwrap if wrapped
        Throwable actual = e.getCause() != null ? e.getCause() : e;

        if (actual instanceof FirebaseAuthException authEx) {
            String errorCode = String.valueOf(authEx.getErrorCode());
            logger.warn("FirebaseAuthException occurred: code={}, message={}", errorCode, authEx.getMessage());

            return switch (errorCode) {
                case "USER_NOT_FOUND", "NOT_FOUND", "user-not-found", "invalid-email", "EMAIL_NOT_FOUND", "INVALID_EMAIL" ->
                        AuthException.accountNotFound();
                case "WRONG_PASSWORD", "wrong-password", "INVALID_PASSWORD" ->
                        AuthException.invalidCredentials();
                case "USER_DISABLED", "user-disabled" ->
                        AuthException.accountDisabled();
                case "TOO_MANY_ATTEMPTS_TRY_LATER", "too-many-requests" ->
                        AuthException.rateLimitExceeded();
                case "EMAIL_NOT_VERIFIED" ->
                        AuthException.emailNotVerified();
                default -> new AuthException("Authentication failed: " + errorCode, HttpStatus.UNAUTHORIZED);
            };
        }

        if (actual instanceof FirebaseRestAuthException restEx) {
            String errorCode = restEx.getErrorCode();
            logger.warn("FirebaseRestAuthException occurred: code={}, message={}", errorCode, restEx.getMessage());

            return switch (errorCode) {
                case "EMAIL_NOT_FOUND", "INVALID_EMAIL" -> AuthException.accountNotFound();
                case "INVALID_PASSWORD" -> AuthException.invalidCredentials();
                case "USER_DISABLED" -> AuthException.accountDisabled();
                case "TOO_MANY_ATTEMPTS_TRY_LATER" -> AuthException.rateLimitExceeded();
                default -> new AuthException("Authentication failed: " + errorCode, HttpStatus.UNAUTHORIZED);
            };
        }
        // Handle Spring Security exceptions
        if (actual instanceof BadCredentialsException) {
            return AuthException.invalidCredentials();
        }

        if (actual instanceof DisabledException) {
            return AuthException.accountDisabled();
        }

        if (actual instanceof AuthenticationServiceException) {
            return new AuthException("Authentication failed", HttpStatus.UNAUTHORIZED);
        }

        // For other exceptions, return AuthException
        logger.error("Unhandled auth exception: {} - {}", actual.getClass().getSimpleName(), actual.getMessage(), actual);
        return new AuthException("Unexpected error occurred during login", HttpStatus.INTERNAL_SERVER_ERROR);
    }

    public void logAuthFailure(String email, Throwable error) {
        firestore.collection("auth_logs").add(Map.of(
                "email", email,
                "status", ActionType.LOGIN_FAILED,
                "error", error.getMessage(),
                "timestamp", FieldValue.serverTimestamp()
        ));
    }

    public void logAuthSuccess(String email) {
        firestore.collection("auth_logs").add(Map.of(
                "email", email,
                "status", ActionType.LOGIN_SUCCESS,
                "timestamp", FieldValue.serverTimestamp()
        ));
    }
    public <T> Mono<T> handleAuthErrors(Mono<T> mono) {
        return mono.onErrorMap(e -> {
            // If it's already an AuthException, keep it
            if (e instanceof AuthException) {
                return e;
            }
            // Otherwise translate it
            return translateFirebaseException(e);
        });
    }

    public void updateLastLogin(String userId, String ipAddress) {
        Instant lastLoginTimestamp = Instant.now();  // Current timestamp

        // Create the update map with last login data
        Map<String, Object> updates = Map.of(
                "lastLogin", Timestamp.of(Date.from(lastLoginTimestamp)),
                "lastLoginTimestamp", Timestamp.of(Date.from(lastLoginTimestamp)),
                "lastLoginIp", ipAddress,
                "lastLoginIpAddress", ipAddress
        );

        // Asynchronously update Firestore and return a Mono
        ApiFuture<WriteResult> future = firestore.collection(COLLECTION_USERS).document(userId).update(updates);

        // Convert ApiFuture to CompletableFuture and then to Mono
        Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                .doOnSuccess(ignored -> logger.info("Successfully updated last login for user {} from {}", userId, ipAddress))
                .doOnError(e -> logger.error("Error updating last login for {}: {}", userId, e.getMessage(), e))
                .onErrorResume(e -> {
                    logger.warn("Failed to update last login for user {}. Proceeding without failure.", userId);
                    return Mono.empty();
                })
                .then();
    }

    public Mono<Void> rollbackFirebaseUserCreation(String email) {
        return Mono.fromCallable(() -> {
                    UserRecord userRecord = firebaseAuth.getUserByEmail(email);
                    if (userRecord != null) {
                        firebaseAuth.deleteUser(userRecord.getUid());
                        logger.info("Rolled back Firebase user: {}", email);
                    }
                    return Mono.empty();
                })
                .subscribeOn(Schedulers.boundedElastic()) // Non-blocking Firebase operation
                .then();
    }
    public Mono<Void> cleanupFailedRegistration(String email) {
        return Mono.fromCallable(() -> {
            try {
                UserRecord user = firebaseAuth.getUserByEmail(email);
                firebaseAuth.deleteUser(user.getUid());
                logger.info("Cleaned up failed registration for {}", email);
                redisCacheService.removeRegisteredEmail(email);
                metricsService.incrementCounter("user.registration.cleanup");
                return null;
            } catch (FirebaseAuthException e) {
                logger.error("Failed to cleanup registration for {}", email, e);
                throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to cleanup registration");
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
    public Mono<Boolean> existsByEmail(String email) {
        return Mono.fromCallable(() ->
                        firestore.collection(COLLECTION_USERS)
                                .whereEqualTo("email", email)
                                .limit(1)
                                .get()
                ).flatMap(future ->
                        Mono.fromFuture(FirestoreUtil.toCompletableFuture(future))
                ).map(snapshot -> !snapshot.isEmpty())
                .subscribeOn(Schedulers.boundedElastic());
    }

    //Purpose: To retrieve the full application-specific User object stored in your Firestore database.
    //Best Used For: Operations requiring the full user profile data (e.g., retrieving custom metadata, roles, or running business logic).
    public Mono<User> findByEmail(String email) {
        return Mono.fromCallable(() ->
                firestore.collection(COLLECTION_USERS)
                        .whereEqualTo("email", email)
                        .limit(1)
                        .get()
        ).flatMap(apiFuture ->
                Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture))
                        .subscribeOn(Schedulers.boundedElastic())
        ).flatMap(querySnapshot -> {
            // Handle empty results
            if (querySnapshot.isEmpty()) {
                return Mono.error(new UserNotFoundException("User not found with email: " + email));
            }

            DocumentSnapshot document = querySnapshot.getDocuments().getFirst();

            // ✅ MUST USE FirestoreUserMapper - remove all toObject(User.class)
            User user = FirestoreUserMapper.documentToUser(document);

            if (user == null) {
                return Mono.error(new DataMappingException("Failed to map user document"));
            }

            // ✅ ALWAYS use .thenReturn(user) - never Mono.empty()
            return Mono.just(user);
        });
    }

    public Mono<User> getUserById(String id) {
        // Get document reference
        DocumentReference userDocRef = firestore.collection(COLLECTION_USERS).document(id);

        return Mono.fromFuture(() ->
                        FirestoreUtil.toCompletableFuture(userDocRef.get())
                )
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(documentSnapshot -> {
                    if (!documentSnapshot.exists()) {
                        // ✅ Throw exception, never Mono.empty()
                        return Mono.error(new UserNotFoundException(
                                "User not found with ID: " + id
                        ));
                    }

                    // ✅ ALWAYS use FirestoreUserMapper
                    User user = FirestoreUserMapper.documentToUser(documentSnapshot);

                    if (user == null) {
                        return Mono.error(new DataMappingException(
                                "Failed to map user document"
                        ));
                    }

                    // ✅ Always return user
                    return Mono.just(user);
                })
                .onErrorResume(ex -> {
                    if (ex instanceof UserNotFoundException) {
                        return Mono.error(ex);
                    }

                    logger.error("Error fetching user by ID [{}]: {}", id, ex.getMessage(), ex);
                    return Mono.error(new AuthException(
                            "Database error fetching user",
                            HttpStatus.INTERNAL_SERVER_ERROR
                    ));
                });
    }
    public Mono<User> findUserByStatus(User.Status status) {
        return Mono.fromCallable(() ->
                        firestore.collection(COLLECTION_USERS)
                                .whereEqualTo("status", status.name())
                                .limit(1)
                                .get()
                )
                .flatMap(apiFuture ->
                        Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture))
                                .subscribeOn(Schedulers.boundedElastic())
                )
                .flatMap(querySnapshot -> {
                    if (querySnapshot == null || querySnapshot.isEmpty()) {
                        logger.warn("No user found with status [{}]", status);

                        // ✅ FIX: Throw a specific exception for "not found"
                        return Mono.error(new UserNotFoundException(
                                "No user found with status: " + status.name()
                        ));
                    }

                    QueryDocumentSnapshot document = querySnapshot.getDocuments().getFirst();
                    User user = FirestoreUserMapper.documentToUser(document);

                    if (user == null) {
                        logger.error("❌ Failed to map User document for status [{}]", status);
                        return Mono.error(new DataMappingException(
                                "Failed to map Firestore document to User for status: " + status
                        ));
                    }

                    // ✅ Always use .thenReturn(user) pattern
                    return Mono.just(user);
                })
                .onErrorResume(ex -> {
                    // Don't wrap "not found" exceptions - let them propagate
                    if (ex instanceof UserNotFoundException) {
                        return Mono.error(ex);
                    }

                    logger.error("Error fetching user by status [{}]: {}", status, ex.getMessage(), ex);
                    return Mono.error(new AuthException(
                            "Failed to fetch user info from Firestore",
                            HttpStatus.INTERNAL_SERVER_ERROR
                    ));
                });
    }

    public Flux<User> findAllUsersByStatus(User.Status status) {
        // 1. Define the Firestore operation within a Mono<ApiFuture<QuerySnapshot>>
        // Use Mono.fromCallable to wrap the blocking Firestore I/O
        return Mono.fromCallable(() ->
                        firestore.collection(COLLECTION_USERS)
                                .whereEqualTo("status", status.name())
                                .get()
                )
                // 2. Convert ApiFuture<QuerySnapshot> to a reactive stream (Mono<QuerySnapshot>)
                // and schedule the blocking I/O on Schedulers.boundedElastic()
                .flatMap(apiFuture ->
                        Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture))
                                .subscribeOn(Schedulers.boundedElastic()) // ✅ Offload I/O
                )
                // 3. Process the QuerySnapshot and transform it into a Flux<User>
                .flatMapMany(querySnapshot -> {
                    if (querySnapshot == null || querySnapshot.isEmpty()) {
                        logger.warn("⚠️ No users found with status [{}]", status);
                        // For a Flux, Flux.empty() is the correct, standard reactive signal for "no results."
                        return Flux.empty();
                    }

                    // 4. Map the list of documents to User objects
                    return Flux.fromIterable(querySnapshot.getDocuments())
                            // ❌ FIX: Remove doc.toObject(User.class)
                            // ✅ FIX: Use FirestoreUserMapper
                            .map(FirestoreUserMapper::documentToUser)
                            // Filter out any potential null results if the mapper fails for a specific document
                            .filter(Objects::nonNull);
                })
                // 5. Error handling
                .onErrorResume(ex -> {
                    logger.error("🔥 Error fetching users by status [{}]: {}", status, ex.getMessage(), ex);
                    // The return type must be Flux<User>, so return Flux.error
                    return Flux.error(new AuthException("Failed to fetch user list from Firestore", HttpStatus.INTERNAL_SERVER_ERROR));
                });
    }

    /**
     * Get pending users with comprehensive approval context
     */
    public Flux<PendingUserResponse> getPendingUsersWithApprovalContext(SecurityContext securityContext) {
        logger.info("📋 Fetching pending users - Requester: {} ({})",
                securityContext.getRequesterEmail(), securityContext.getRequesterRole());

        return findAllUsersByStatus(User.Status.PENDING_APPROVAL)
                .map(user -> buildPendingUserResponse(user, securityContext))
                .doOnNext(response ->
                        logger.debug("👤 Pending user processed: {} | Can Approve: {}",
                                response.getEmail(), response.isCanApprove()));
    }

    private PendingUserResponse buildPendingUserResponse(User user, SecurityContext securityContext) {
        return PendingUserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles())
                .status(user.getStatus())
                .approvalLevel(user.getApprovalLevel().orElse(RoleAssignmentService.ApprovalLevel.MANAGER_OR_ABOVE))
                .createdAt(user.getCreatedAt() != null ? user.getCreatedAt() : Instant.now())
                .department(user.getDepartment() != null ? user.getDepartment() : "")
                .canApprove(roleAssignmentService.canApproveUser(securityContext, user))
                .requesterContext(buildRequesterContext(securityContext))
                .build();
    }

    private RequesterContext buildRequesterContext(SecurityContext securityContext) {
        return RequesterContext.builder()
                .requesterEmail(securityContext.getRequesterEmail())
                .requesterRole(securityContext.getRequesterRole())
                .timestamp(Instant.now())
                .build();
    }

    public Mono<Map<String, Object>> getDocument(String collection, String documentId) {
        return Mono.fromCallable(() -> {
                    DocumentReference docRef = firestore.collection(collection).document(documentId);
                    ApiFuture<DocumentSnapshot> future = docRef.get();
                    DocumentSnapshot document = future.get();
                    return document.exists() ? document.getData() : null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> Mono.empty());
    }

    public Mono<Void> setDocument(String collection, String documentId, Map<String, Object> data) {
        return Mono.fromCallable(() -> {
                    DocumentReference docRef = firestore.collection(collection).document(documentId);
                    ApiFuture<WriteResult> future = docRef.set(data);
                    future.get(); // Wait for the operation to complete
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }
    /**
     * Retrieves all user documents from the Firestore 'users' collection.
     * The operation is performed on a boundedElastic scheduler as it involves blocking I/O (Firestore sync call).
     *
     * @return Flux of User objects found in the collection.
     */
    // Your original code with minimal fixes:
    public Flux<User> findAllUsers() {
        return Flux.defer(() -> {
                    logger.debug("🔍 Retrieving all users from Firestore"); // Changed to debug

                    CollectionReference usersCollection = firestore.collection(COLLECTION_USERS);
                    ApiFuture<QuerySnapshot> future = usersCollection.get();

                    return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                            .flatMapMany(querySnapshot -> {
                                if (querySnapshot.isEmpty()) {
                                    logger.debug("No users found");
                                    return Flux.empty(); // ✅ This is OK in Flux context
                                }

                                List<User> users = new ArrayList<>();
                                for (DocumentSnapshot document : querySnapshot.getDocuments()) {
                                    try {
                                        // ✅ ALWAYS use FirestoreUserMapper
                                        User user = FirestoreUserMapper.documentToUser(document);
                                        if (user != null) {
                                            users.add(user);
                                        } else {
                                            logger.warn("⚠️ FirestoreUserMapper returned null for document: {}", document.getId());
                                        }
                                    } catch (Exception e) {
                                        logger.error("❌ Error mapping document {}: {}", document.getId(), e.getMessage());
                                        // Continue processing other documents
                                    }
                                }

                                logger.info("✅ Retrieved {} users", users.size());
                                return Flux.fromIterable(users); // ✅ Always return Flux with users
                            })
                            .onErrorResume(e -> { // Changed to onErrorResume
                                logger.error("❌ Failed to fetch users: {}", e.getMessage(), e);
                                return Flux.error(new CustomException(
                                        HttpStatus.INTERNAL_SERVER_ERROR,
                                        "Failed to retrieve users"
                                ));
                            });
                })
                .subscribeOn(Schedulers.boundedElastic());
    }
    public Flux<User> findActiveUsers() {
        logger.debug("🔍 Retrieving active users from Firestore");

        return Mono.fromCallable(() ->
                        firestore.collection(COLLECTION_USERS)
                                .whereEqualTo("status", User.Status.ACTIVE.name())
                                .whereEqualTo("enabled", true)
                                .get()
                )
                .flatMap(apiFuture ->
                        Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(apiFuture))
                                .subscribeOn(Schedulers.boundedElastic())
                )
                .flatMapMany(this::mapQuerySnapshotToUsers)
                .onErrorResume(this::handleUserRetrievalError);
    }

    private Flux<User> mapQuerySnapshotToUsers(QuerySnapshot querySnapshot) {
        if (querySnapshot.isEmpty()) {
            logger.debug("No active users found");
            return Flux.empty();
        }

        List<DocumentSnapshot> documents = new ArrayList<>(querySnapshot.getDocuments());
        List<User> users = FirestoreUserMapper.mapToUsers(documents);

        logger.info("✅ Retrieved {} active users", users.size());
        return Flux.fromIterable(users);
    }

    private Flux<User> handleUserRetrievalError(Throwable e) {
        logger.error("❌ Error fetching active users: {}", e.getMessage(), e);
        return Flux.error(new CustomException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to retrieve active users"
        ));
    }
    /**
     * Deletes a user completely from both Firebase Authentication and Firestore.
     *
     * @param userId The ID of the user to delete.
     * @return Mono<Void> signal upon successful completion.
     */
    public Mono<Void> deleteUser(String userId) {
        if (userId == null) {
            return Mono.error(new IllegalArgumentException("User ID cannot be null for deletion."));
        }

        // 1. Delete from Firebase Authentication (Blocking Call)
        Mono<Void> deleteFirebaseAuth = Mono.fromCallable(() -> {
                    firebaseAuth.deleteUser(userId);
                    logger.info("🔥 Successfully deleted user from Firebase Auth: {}", userId);
                    return (Void) null;
                }).subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(FirebaseAuthException.class, e -> {
                    if ("USER_NOT_FOUND".equals(e.getAuthErrorCode().name())) {
                        logger.warn("⚠️ User not found in Firebase Auth, proceeding with Firestore deletion: {}", userId);
                        return new UserNotFoundException("User not found in Auth, proceeding with data cleanup.");
                    }
                    logger.error("❌ Firebase Auth deletion failed for {}: {}", userId, e.getMessage());
                    return new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to delete user in Firebase Auth.");
                })
                // Treat UserNotFoundException as success for flow control
                .onErrorResume(UserNotFoundException.class, e -> Mono.empty());


        // 2. Delete main User document and subcollections from Firestore
        Mono<Void> deleteFirestoreUser = Mono.defer(() -> {
            logger.warn("🗑️ Initiating Firestore data cleanup for user: {}", userId);

            // Deleting the main user document
            DocumentReference userRef = firestore.collection(COLLECTION_USERS).document(userId);

            // Note: Firestore does not automatically delete subcollections when the parent document is deleted.
            // A full deletion would require iterating and deleting documents in all subcollections:
            // - COLLECTION_USER_PROFILES
            // - COLLECTION_USER_PASSWORD_HISTORY
            // - COLLECTION_USER_PERMISSIONS
            // For simplicity in this example, we only delete the main document, which is often sufficient
            // for soft-deletion/archival or when using a dedicated cleanup utility.

            ApiFuture<WriteResult> future = userRef.delete();

            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .doOnSuccess(result ->
                            logger.info("✅ Successfully deleted main user document from Firestore: {}", userId))
                    .doOnError(error ->
                            logger.error("❌ Failed to delete main user document from Firestore: {}", userId))
                    .onErrorMap(e -> new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to delete user data from Firestore."))
                    .then();
        }).subscribeOn(Schedulers.boundedElastic());


        // 3. Execute both deletion steps sequentially
        return deleteFirebaseAuth
                .then(deleteFirestoreUser);
    }
    public Mono<Void> deleteDocument(String collection, String documentId) {
        logger.warn("🗑️ Deleting Firestore document: {}/{}", collection, documentId);

        DocumentReference docRef = firestore.collection(collection).document(documentId);
        ApiFuture<WriteResult> future = docRef.delete();

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(result -> logger.info("✅ Deleted document: {}/{}", collection, documentId))
                .doOnError(error -> logger.error("❌ Failed to delete {}/{}: {}", collection, documentId, error.getMessage()))
                .onErrorMap(e -> new RuntimeException("Failed to delete Firestore document", e))
                .then();
    }

    /**
     * Saves or updates the main User document in the Firestore 'users' collection.
     * This is an asynchronous operation using Reactor for non-blocking execution.
     *
     * @param user The User object to save (assumes ID is already set).
     * @return Mono<User> containing the saved user.
     */
    public Mono<User> save(User user) {
        return Mono.defer(() -> {
            logger.info("💾 Initiating save/update for user: {}", user.getId());

            // 1. Convert the User object to a Map for Firestore (to ensure specific field control)
            Map<String, Object> userData = new HashMap<>();
            // Only include fields that should be updated frequently (avoid overwriting timestamps, etc.)
            userData.put("firstName", user.getFirstName());
            userData.put("lastName", user.getLastName());
            userData.put("phoneNumber", user.getPhoneNumber());
            userData.put("department", user.getDepartment());
            userData.put("status", user.getStatus().name());
            userData.put("enabled", user.isEnabled());
            userData.put("accountLocked", user.isAccountLocked());
            userData.put("forcePasswordChange", user.isForcePasswordChange());
            userData.put("roleNames", user.getRoleNames());
            userData.put("permissions", user.getPermissions() != null ? user.getPermissions() : Collections.emptyList());
            userData.put("updatedAt", Instant.now()); // Update timestamp

            DocumentReference userRef = firestore.collection(COLLECTION_USERS).document(user.getId());
            ApiFuture<WriteResult> future = userRef.update(userData);

            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .doOnSuccess(result ->
                            logger.info("✅ Firestore user update successful for {} at {}", user.getId(), result.getUpdateTime()))
                    .doOnError(error ->
                            logger.error("❌ Firestore user update failed for {}: {}", user.getId(), error.getMessage()))
                    .thenReturn(user); // Return the original user object on success
        }).subscribeOn(Schedulers.boundedElastic());
    }
    public Mono<Void> updateUserInFirestore(User user) {
        return Mono.defer(() -> {
            // 1. Convert the User object to a Map for Firestore (to ensure specific field control)
            Map<String, Object> userData = new HashMap<>();
            // Only include fields that should be updated frequently (avoid overwriting timestamps, etc.)
            userData.put("firstName", user.getFirstName());
            userData.put("lastName", user.getLastName());
            userData.put("phoneNumber", user.getPhoneNumber());
            userData.put("department", user.getDepartment());
            userData.put("status", user.getStatus().name());
            userData.put("enabled", user.isEnabled());
            userData.put("accountLocked", user.isAccountLocked());
            userData.put("forcePasswordChange", user.isForcePasswordChange());
            userData.put("roleNames", user.getRoleNames());
            userData.put("permissions", user.getPermissions() != null ? user.getPermissions() : Collections.emptyList());
            userData.put("updatedAt", Instant.now()); // Update timestamp

            DocumentReference userRef = firestore.collection(COLLECTION_USERS).document(user.getId());
            ApiFuture<WriteResult> future = userRef.update(userData);
            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .doOnSuccess(result ->
                            logger.info("✅ Firestore user {} updated successfully", user.getEmail()))
                    .doOnError(e ->
                            logger.error("❌ Failed to update Firestore user {}: {}", user.getEmail(), e.getMessage()))
                    .thenReturn(user);
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
}