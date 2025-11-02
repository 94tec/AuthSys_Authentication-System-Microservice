package com.techStack.authSys.service;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.database.GenericTypeIndicator;
import com.techStack.authSys.config.FirebaseConfig;
import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.exception.*;
import com.techStack.authSys.models.*;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.repository.PermissionProvider;
import com.techStack.authSys.util.FirestoreUtil;
import io.jsonwebtoken.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;


import java.net.SocketException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
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
    private final RedisCacheService redisCacheService;
    private final PermissionProvider permissionProvider;

    @Autowired
    public FirebaseServiceAuth(Firestore firestore,
                               EncryptionService encryptionService,
                               FirebaseAuth firebaseAuth,
                               DeviceVerificationService deviceVerificationService,
                               FirebaseConfig firebaseConfig,
                               MetricsService metricsService,
                               RedisCacheService redisCacheService,
                               PermissionProvider permissionProvider) {
        this.firestore = firestore;
        this.encryptionService = encryptionService;
        this.firebaseAuth = firebaseAuth;
        this.deviceVerificationService = deviceVerificationService;
        this.firebaseConfig = firebaseConfig;
        this.permissionProvider = permissionProvider;
        this.metricsService = metricsService;
        this.redisCacheService = redisCacheService;
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
        return Mono.fromCallable(() -> {
                    // Create user in Firebase Authentication
                    UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                            .setEmail(userDto.getEmail())
                            .setEmailVerified(false)
                            .setPassword(userDto.getPassword())
                            .setDisabled(false);

                    if (userDto.getPhoneNumber() != null) {
                        request.setPhoneNumber(userDto.getPhoneNumber());
                    }

                    if (userDto.getFirstName() != null && userDto.getLastName() != null) {
                        request.setDisplayName(userDto.getFirstName() + " " + userDto.getLastName());
                    }

                    return firebaseAuth.createUser(request);
                })
                .subscribeOn(Schedulers.boundedElastic()) // Ensure Firebase API calls are non-blocking
                .flatMap(userRecord -> Mono.fromCallable(() -> encryptionService.encrypt(userDto.getPassword()))
                        .subscribeOn(Schedulers.boundedElastic())
                        .map(encryptedPassword -> {
                            // Determine if user has privileged role
                            boolean isPrivileged = userDto.getRoles().stream()
                                    .anyMatch(role -> role.equalsIgnoreCase("ADMIN") ||
                                            role.equalsIgnoreCase("SUPER_ADMIN") ||
                                            role.equalsIgnoreCase("MANAGER"));

                            return User.builder()
                                    .id(userRecord.getUid())
                                    .firstName(userDto.getFirstName())
                                    .lastName(userDto.getLastName())
                                    .email(userDto.getEmail())
                                    .username(userDto.getUsername())
                                    .identityNo(userDto.getIdentityNo())
                                    .phoneNumber(userDto.getPhoneNumber())
                                    .roleNames(
                                            userDto.getRoles().stream()
                                                    .map(role -> Roles.fromName(role)
                                                            .orElseThrow(() -> new IllegalArgumentException("Invalid role: " + role)))
                                                    .map(Roles::name)
                                                    .collect(Collectors.toList())
                                    )
                                    .enabled(isPrivileged) // Auto-enable for privileged roles
                                    .emailVerified(false)
                                    .accountLocked(false)
                                    .password(encryptedPassword)
                                    .lastPasswordChangeDate(LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE))
                                    .deviceFingerprint(deviceFingerprint)
                                    .status(isPrivileged ? User.Status.ACTIVE : User.Status.PENDING_APPROVAL)
                                    .build();
                        }))
                .flatMap(user -> saveUserToFirestore(user, ipAddress)
                        .then(deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint))
                        //.then(saveUserPermissions(user)) // Save permissions based on role
                        .thenReturn(user))
                .onErrorResume(e -> {
                    logger.error("❌ User creation failed: {}", e.getMessage(), e);
                    return rollbackFirebaseUserCreation(userDto.getEmail()).then(Mono.error(e));
                });
    }
    public Mono<User> saveUser(User user, String ipAddress, String deviceFingerprint) {
        return saveUserToFirestore(user, ipAddress)
                .then(deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint))
                .thenReturn(user);
    }

    private Mono<User> saveUserToFirestore(User user, String ipAddress) {
        return Mono.defer(() -> {
            try {
                // Determine status based on role
                boolean isPrivileged = user.getRoleNames().stream()
                        .anyMatch(role -> role.equalsIgnoreCase("ADMIN") ||
                                role.equalsIgnoreCase("SUPER_ADMIN") ||
                                role.equalsIgnoreCase("MANAGER"));

                User.Status status = isPrivileged ? User.Status.ACTIVE : User.Status.PENDING_APPROVAL;

                // Resolve permissions only for privileged users
                List<String> permissionsList = Collections.emptyList();
                if (isPrivileged) {
                    Set<String> resolvedPermissions = permissionProvider.resolveEffectivePermissions(user);
                    permissionsList = new ArrayList<>(resolvedPermissions);
                    logger.info("✅ Resolved {} permissions for privileged user: {}",
                            permissionsList.size(), user.getEmail());
                } else {
                    logger.info("⚠️ User {} registered with PENDING_APPROVAL status. Permissions will be assigned after approval.",
                            user.getEmail());
                }

                Map<String, Object> userData = new HashMap<>();

                // Basic Info
                userData.put("id", user.getId());
                userData.put("email", user.getEmail());
                userData.put("firstName", user.getFirstName());
                userData.put("lastName", user.getLastName());
                userData.put("username", user.getUsername());
                userData.put("identityNo", user.getIdentityNo());
                userData.put("phoneNumber", user.getPhoneNumber());

                // Roles and Permissions
                userData.put("roleNames", user.getRoleNames());
                userData.put("permissions", permissionsList);
                userData.put("requestedRole", user.getRequestedRole() != null ?
                        user.getRequestedRole().name() : null);
                userData.put("department", user.getDepartment());
                userData.put("status", status.name());

                // Security Fields
                userData.put("createdBy", user.getCreatedBy());
                userData.put("forcePasswordChange", user.isForcePasswordChange());
                userData.put("otpSecret", user.getOtpSecret());
                userData.put("mfaRequired", user.isMfaRequired());
                userData.put("enabled", isPrivileged); // Auto-enable privileged users
                userData.put("accountLocked", user.isAccountLocked());
                userData.put("emailVerified", user.isEmailVerified());
                userData.put("loginAttempts", user.getLoginAttempts());
                userData.put("failedLoginAttempts", user.getFailedLoginAttempts());

                // Timestamps
                userData.put("createdAt", Instant.now());
                userData.put("lastLogin", user.getLastLogin());
                userData.put("lastLoginTimestamp", user.getLastLoginTimestamp());
                userData.put("lastLoginIp", user.getLastLoginIp());
                userData.put("lastLoginIpAddress", user.getLastLoginIpAddress());

                // Verification Tokens
                userData.put("verificationToken", user.getVerificationToken());
                userData.put("verificationTokenHash", user.getVerificationTokenHash());
                userData.put("verificationTokenExpiresAt", user.getVerificationTokenExpiresAt());
                userData.put("passwordResetToken", user.getPasswordResetToken());
                userData.put("lastPasswordChangeDate", user.getLastPasswordChangeDate());

                // Profile References
                userData.put("profilePictureUrl", user.getProfilePictureUrl());
                userData.put("bio", user.getBio());
                userData.put("userProfileId", user.getUserProfileId());
                userData.put("deviceFingerprint", user.getDeviceFingerprint());

                // Build UserProfile
                UserProfile userProfile = UserProfile.builder()
                        .userId(user.getId())
                        .firstName(user.getFirstName())
                        .lastName(user.getLastName())
                        .profilePictureUrl("")
                        .bio("")
                        .isPublic(true)
                        .build();

                // Build Password History
                UserPasswordHistory userPasswordHistory = UserPasswordHistory.builder()
                        .password(encryptionService.encrypt(user.getPassword()))
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
                            logger.info("✅ User status: {}", status);
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
    public Mono<Boolean> checkEmailAvailability(String email) {
        return Mono.defer(() -> {
            try {
                FirebaseAuth.getInstance().getUserByEmail(email);
                // User exists
                return Mono.just(true);
            } catch (FirebaseAuthException e) {
                if ("USER_NOT_FOUND".equals(e.getAuthErrorCode().name())) {
                    // Email is available
                    return Mono.just(false);
                }
                return Mono.error(new CustomException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Firebase error: " + e.getMessage()
                ));
            }
        });
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

                    User user = userDoc.toObject(User.class);
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
                redisCacheService.invalidateEmailRegistration(email);
                metricsService.incrementCounter("user.registration.cleanup");
                return null;
            } catch (FirebaseAuthException e) {
                logger.error("Failed to cleanup registration for {}", email, e);
                throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to cleanup registration");
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
    public Mono<User> findByEmail(String email) {
        return Mono.fromCallable(() ->
                firestore.collection(COLLECTION_USERS)
                        .whereEqualTo("email", email)
                        .limit(1)
                        .get()
        ).flatMap(apiFuture ->
                Mono.fromFuture(toCompletableFuture(apiFuture))
                        .subscribeOn(Schedulers.boundedElastic()) // Offload blocking
        ).flatMap(querySnapshot -> {
            if (querySnapshot.isEmpty()) {
                return Mono.empty();
            }
            return Mono.just(querySnapshot.getDocuments().get(0).toObject(User.class));
        });
    }
    public Mono<User> getUserById(String id) {
        return Mono.fromCallable(() ->
                        firestore.collection(COLLECTION_USERS)
                                .whereEqualTo("id", id)
                                .limit(1)
                                .get()
                ).flatMap(apiFuture ->
                        Mono.fromFuture(toCompletableFuture(apiFuture))
                                .subscribeOn(Schedulers.boundedElastic()) // Offload blocking
                ).flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        logger.warn("User with ID [{}] not found in Firestore", id);
                        return Mono.empty();
                    }
                    return Mono.just(querySnapshot.getDocuments().get(0).toObject(User.class));
                })
                .onErrorResume(ex -> {
                    logger.error("Error fetching user by ID [{}]: {}", id, ex.getMessage(), ex);
                    return Mono.error(new AuthException("Failed to fetch user info", HttpStatus.INTERNAL_SERVER_ERROR));
                });
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

    private <T> CompletableFuture<T> toCompletableFuture(ApiFuture<T> apiFuture) {
        CompletableFuture<T> completableFuture = new CompletableFuture<>();
        apiFuture.addListener(
                () -> {
                    try {
                        completableFuture.complete(apiFuture.get());
                    } catch (Exception e) {
                        completableFuture.completeExceptionally(e);
                    }
                },
                Runnable::run
        );
        return completableFuture;
    }
}