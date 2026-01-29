package com.techStack.authSys.service.auth;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.config.intergration.FirebaseConfig;
import com.techStack.authSys.dto.response.PendingUserResponse;
import com.techStack.authSys.dto.internal.RequesterContext;
import com.techStack.authSys.dto.internal.SecurityContext;
import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.exception.auth.AuthenticationException;
import com.techStack.authSys.exception.auth.FirebaseRestAuthException;
import com.techStack.authSys.exception.data.DataMappingException;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserPasswordHistory;
import com.techStack.authSys.models.user.UserProfile;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.service.security.EncryptionService;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.util.firebase.FirestoreUserMapper;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
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
import java.util.stream.Collectors;

/**
 * Firebase Authentication and User Management Service
 * - Consolidated permission logic
 * - Better error handling and logging
 * - Consistent document structure
 * - Atomic operations for data integrity
 */
@Component
public class FirebaseServiceAuth {

    private static final Logger logger = LoggerFactory.getLogger(FirebaseServiceAuth.class);

    // Collection names
    private static final String COLLECTION_USERS = "users";
    private static final String COLLECTION_USER_PROFILES = "user_profiles";
    private static final String COLLECTION_USER_PASSWORD_HISTORY = "user_password_history";
    private static final String COLLECTION_USER_PERMISSIONS = "user_permissions";
    private static final String COLLECTION_AUTH_LOGS = "auth_logs";

    // Fixed document IDs for easy retrieval
    private static final String PROFILE_DOC_ID = "profile";
    private static final String ACTIVE_PERMISSIONS_DOC_ID = "active_permissions";

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
    public FirebaseServiceAuth(
            Firestore firestore,
            EncryptionService encryptionService,
            FirebaseAuth firebaseAuth,
            DeviceVerificationService deviceVerificationService,
            FirebaseConfig firebaseConfig,
            MetricsService metricsService,
            RedisUserCacheService redisCacheService,
            @Lazy RoleAssignmentService roleAssignmentService,
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

    // ============================================================================
    // USER CREATION - MAIN ENTRY POINTS
    // ============================================================================

    /**
     * Creates a Super Admin user with immediate full permissions
     */
    public Mono<User> createSuperAdmin(User user, String password, String ipAddress, String deviceFingerprint) {
        return createFirebaseAuthUser(user.getEmail(), password, user.getPhoneNumber(), true)
                .map(userRecord -> {
                    User mappedUser = mapFirebaseUserToDomain(userRecord, user);
                    // Set super admin specific properties
                    mappedUser.setRoleNames(Arrays.asList(Roles.SUPER_ADMIN.name(), Roles.ADMIN.name()));
                    mappedUser.setEnabled(true);
                    mappedUser.setStatus(User.Status.ACTIVE);
                    mappedUser.setEmailVerified(true);
                    return mappedUser;
                })
                .flatMap(mappedUser -> saveUserWithRolesAndPermissions(mappedUser, ipAddress, deviceFingerprint))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Creates a regular user from UserDTO with proper role/permission handling
     */
    public Mono<User> createFirebaseUser(UserDTO userDto, String ipAddress, String deviceFingerprint) {
        return createFirebaseAuthUser(userDto.getEmail(), userDto.getPassword(), userDto.getPhoneNumber(), false)
                .zipWith(encryptPassword(userDto.getPassword()))  // Creates Tuple2<UserRecord, String>
                .map(tuple -> buildLocalUserModel(
                        tuple.getT1(),           // UserRecord
                        userDto,                 // UserDTO
                        tuple.getT2(),           // encrypted password
                        deviceFingerprint        // device fingerprint
                ))
                .flatMap(user -> saveUserWithRolesAndPermissions(user, ipAddress, deviceFingerprint))
                .onErrorResume(e -> rollbackFirebaseUserCreation(userDto.getEmail()).then(Mono.error(e)));
    }

    // ============================================================================
    // FIREBASE AUTH USER CREATION
    // ============================================================================

    /**
     * Unified Firebase Auth user creation
     */
    private Mono<UserRecord> createFirebaseAuthUser(
            String email,
            String password,
            String phoneNumber,
            boolean emailVerified) {

        return Mono.fromCallable(() -> {
            UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                    .setEmail(email)
                    .setPassword(password)
                    .setEmailVerified(emailVerified)
                    .setDisabled(false);

            if (phoneNumber != null) {
                request.setPhoneNumber(phoneNumber);
            }

            return firebaseAuth.createUser(request);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ============================================================================
    // USER MODEL BUILDING
    // ============================================================================

    /**
     * Maps Firebase UserRecord to domain User model
     */
    private User mapFirebaseUserToDomain(UserRecord userRecord, User baseUser) {
        Instant now = Instant.now();
        baseUser.setId(userRecord.getUid());
        baseUser.setCreatedAt(now);
        baseUser.setUpdatedAt(now);
        return baseUser;
    }

    /**
     * Builds local User model from UserDTO
     */
    private User buildLocalUserModel(
            UserRecord userRecord,
            UserDTO userDto,
            String encryptedPassword,
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
                .enabled(false)
                .emailVerified(false)
                .accountLocked(false)
                .password(encryptedPassword)
                .lastPasswordChangeDate(LocalDate.now().toString())
                .deviceFingerprint(deviceFingerprint)
                .status(User.Status.PENDING_APPROVAL)
                .permissions(new ArrayList<>())
                .build();
    }

    // ============================================================================
    // ATOMIC SAVE WITH ROLES & PERMISSIONS
    // ============================================================================

    /**
     * Atomic save: User + Profile + Password History + Permissions in one batch
     */
    private Mono<User> saveUserWithRolesAndPermissions(User user, String ipAddress, String deviceFingerprint) {
        return Mono.defer(() -> {
            try {
                boolean isPrivileged = isPrivilegedUser(user);
                PermissionData permissionData = resolvePermissionData(user, isPrivileged);

                Map<String, Object> userData = FirestoreUserMapper.userToMap(user);
                ensureTimestamps(userData);

                UserProfile userProfile = buildUserProfile(user);
                UserPasswordHistory passwordHistory = buildPasswordHistory(user, ipAddress);
                Map<String, Object> permissionsDoc = buildPermissionsDocument(user, permissionData, isPrivileged);

                return executeBatchWrite(user, userData, userProfile, passwordHistory, permissionsDoc)
                        .then(deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint))
                        .thenReturn(user);

            } catch (Exception e) {
                logger.error("❌ Error preparing user data for {}: {}", user.getEmail(), e.getMessage(), e);
                return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to prepare user data"));
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Execute atomic Firestore batch write
     */
    private Mono<Void> executeBatchWrite(
            User user,
            Map<String, Object> userData,
            UserProfile userProfile,
            UserPasswordHistory passwordHistory,
            Map<String, Object> permissionsDoc) {

        WriteBatch batch = firestore.batch();

        DocumentReference userRef = firestore.collection(COLLECTION_USERS).document(user.getId());
        DocumentReference profileRef = firestore.collection(COLLECTION_USERS)
                .document(user.getId())
                .collection(COLLECTION_USER_PROFILES)
                .document(PROFILE_DOC_ID);
        DocumentReference passwordHistoryRef = firestore.collection(COLLECTION_USERS)
                .document(user.getId())
                .collection(COLLECTION_USER_PASSWORD_HISTORY)
                .document();
        DocumentReference permissionsRef = firestore.collection(COLLECTION_USERS)
                .document(user.getId())
                .collection(COLLECTION_USER_PERMISSIONS)
                .document(ACTIVE_PERMISSIONS_DOC_ID);

        batch.set(userRef, userData);
        batch.set(profileRef, userProfile);
        batch.set(passwordHistoryRef, passwordHistory);
        batch.set(permissionsRef, permissionsDoc);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(batch.commit()))
                .doOnSuccess(result -> logger.info("✅ Atomic batch write successful for user {} with status {}",
                        user.getEmail(), permissionsDoc.get("status")))
                .doOnError(error -> logger.error("❌ Atomic batch write failed for user {}: {}",
                        user.getId(), error.getMessage()))
                .retryWhen(Retry.backoff(3, Duration.ofMillis(100)))
                .then();
    }

    // ============================================================================
    // PERMISSION RESOLUTION
    // ============================================================================

    private boolean isPrivilegedUser(User user) {
        return user.getRoleNames().stream()
                .anyMatch(role -> role.equalsIgnoreCase("ADMIN") ||
                        role.equalsIgnoreCase("SUPER_ADMIN") ||
                        role.equalsIgnoreCase("MANAGER"));
    }

    private PermissionData resolvePermissionData(User user, boolean isPrivileged) {
        if (isPrivileged) {
            Set<String> resolvedPermissions = permissionProvider.resolveEffectivePermission(user);

            if (resolvedPermissions.isEmpty()) {
                logger.error("❌ No permissions resolved for privileged user: {}", user.getEmail());
                throw new RuntimeException("Failed to resolve permissions for privileged user");
            }

            logger.info("✅ Resolved {} permissions for privileged user: {}",
                    resolvedPermissions.size(), user.getEmail());

            return new PermissionData(
                    new ArrayList<>(user.getRoleNames()),
                    new ArrayList<>(resolvedPermissions),
                    User.Status.ACTIVE
            );
        } else {
            logger.info("⚠️ Creating PENDING_APPROVAL user: {}. Awaiting manager approval.", user.getEmail());

            return new PermissionData(
                    new ArrayList<>(user.getRoleNames()),
                    Collections.emptyList(),
                    User.Status.PENDING_APPROVAL
            );
        }
    }

    private Map<String, Object> buildPermissionsDocument(User user, PermissionData permData, boolean isPrivileged) {
        Map<String, Object> permissionsDoc = new HashMap<>();

        permissionsDoc.put("userId", user.getId());
        permissionsDoc.put("email", user.getEmail());
        permissionsDoc.put("roles", permData.roles);
        permissionsDoc.put("permissions", permData.permissions);
        permissionsDoc.put("status", permData.status.name());
        permissionsDoc.put("createdAt", Instant.now());
        permissionsDoc.put("updatedAt", Instant.now());

        if (isPrivileged) {
            permissionsDoc.put("approvedBy", user.getCreatedBy() != null ? user.getCreatedBy() : "SYSTEM");
            permissionsDoc.put("approvedAt", Instant.now());
        } else {
            permissionsDoc.put("approvedBy", null);
            permissionsDoc.put("approvedAt", null);
        }

        return permissionsDoc;
    }

    // ============================================================================
    // APPROVAL WORKFLOW
    // ============================================================================

    /**
     * Approve user and grant permissions
     */
    public Mono<Void> approveUserAndGrantPermissions(String userId, String approvedBy) {
        return getUserById(userId)
                .flatMap(user -> {
                    Set<String> resolvedPermissions = permissionProvider.resolveEffectivePermission(user);

                    Map<String, Object> updates = new HashMap<>();
                    updates.put("permissions", new ArrayList<>(resolvedPermissions));
                    updates.put("status", User.Status.ACTIVE.name());
                    updates.put("approvedBy", approvedBy);
                    updates.put("approvedAt", Instant.now());
                    updates.put("updatedAt", Instant.now());

                    DocumentReference permissionsRef = firestore.collection(COLLECTION_USERS)
                            .document(userId)
                            .collection(COLLECTION_USER_PERMISSIONS)
                            .document(ACTIVE_PERMISSIONS_DOC_ID);

                    return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(permissionsRef.update(updates)))
                            .doOnSuccess(result -> logger.info("✅ User {} approved and granted {} permissions",
                                    user.getEmail(), resolvedPermissions.size()))
                            .then();
                });
    }

    /**
     * Get user permissions
     */
    public Mono<Map<String, Object>> getUserPermissions(String userId) {
        DocumentReference permissionsRef = firestore.collection(COLLECTION_USERS)
                .document(userId)
                .collection(COLLECTION_USER_PERMISSIONS)
                .document(ACTIVE_PERMISSIONS_DOC_ID);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(permissionsRef.get()))
                .map(documentSnapshot -> {
                    if (!documentSnapshot.exists()) {
                        throw new CustomException(HttpStatus.NOT_FOUND,
                                "Permissions not found for user: " + userId);
                    }
                    return documentSnapshot.getData();
                });
    }

    // ============================================================================
    // AUTHENTICATION
    // ============================================================================

    public Mono<Void> validateCredentials(String email, String password) {
        return getUserRecord(email)
                .flatMap(userRecord -> signInWithFirebase(email, password))
                .onErrorMap(this::translateFirebaseException);
    }

    public Mono<UserRecord> getUserRecord(String email) {
        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(
                        FirebaseAuth.getInstance().getUserByEmailAsync(email)))
                .onErrorResume(e -> Mono.error(new AuthenticationException("User not found")));
    }

    public Mono<Void> signInWithFirebase(String email, String password) {
        String firebaseAuthUrl = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="
                + firebaseConfig.getFirebaseApiKey();

        return WebClient.create()
                .post()
                .uri(firebaseAuthUrl)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
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
                        }))
                .bodyToMono(Map.class)
                .doOnSuccess(response -> {
                    if (response != null && response.containsKey("idToken")) {
                        logger.info("🔓 User {} authenticated successfully. Firebase UID: {}",
                                email, response.get("localId"));
                    }
                })
                .then();
    }

    // ============================================================================
    // USER RETRIEVAL
    // ============================================================================

    public Mono<User> getUserByEmail(String email) {
        return Mono.fromCallable(() -> FirebaseAuth.getInstance().getUserByEmail(email))
                .subscribeOn(Schedulers.boundedElastic())
                .retryWhen(Retry.backoff(3, Duration.ofMillis(300))
                        .filter(e -> e instanceof SocketException))
                .onErrorResume(e -> {
                    logger.warn("❌ Error fetching user by email '{}': {}", email, e.getMessage());
                    if (e instanceof FirebaseAuthException) {
                        return Mono.error(e);
                    }
                    return Mono.error(new AuthException("Unexpected error during user lookup",
                            HttpStatus.INTERNAL_SERVER_ERROR));
                })
                .flatMap(userRecord -> findByEmail(email));
    }

    public Mono<User> findByEmail(String email) {
        return Mono.fromCallable(() -> firestore.collection(COLLECTION_USERS)
                        .whereEqualTo("email", email)
                        .limit(1)
                        .get())
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        return Mono.error(new UserNotFoundException("User not found with email: " + email));
                    }

                    DocumentSnapshot document = querySnapshot.getDocuments().get(0);
                    User user = FirestoreUserMapper.documentToUser(document);

                    if (user == null) {
                        return Mono.error(new DataMappingException("Failed to map user document"));
                    }

                    return Mono.just(user);
                });
    }

    public Mono<User> getUserById(String id) {
        DocumentReference userDocRef = firestore.collection(COLLECTION_USERS).document(id);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(userDocRef.get()))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(documentSnapshot -> {
                    if (!documentSnapshot.exists()) {
                        return Mono.error(new UserNotFoundException("User not found with ID: " + id));
                    }

                    User user = FirestoreUserMapper.documentToUser(documentSnapshot);

                    if (user == null) {
                        return Mono.error(new DataMappingException("Failed to map user document"));
                    }

                    return Mono.just(user);
                })
                .onErrorResume(ex -> {
                    if (ex instanceof UserNotFoundException || ex instanceof DataMappingException) {
                        return Mono.error(ex);
                    }
                    logger.error("Error fetching user by ID [{}]: {}", id, ex.getMessage(), ex);
                    return Mono.error(new AuthException("Database error fetching user",
                            HttpStatus.INTERNAL_SERVER_ERROR));
                });
    }

    public Mono<User> fetchUserDetailsWithPermissions(String userId) {
        return Mono.fromCallable(() -> {
                    DocumentSnapshot userDoc = firestore.collection(COLLECTION_USERS)
                            .document(userId).get().get();

                    if (!userDoc.exists()) {
                        throw new CustomException(HttpStatus.NOT_FOUND, "User not found");
                    }

                    User user = FirestoreUserMapper.documentToUser(userDoc);
                    if (user == null) {
                        throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                                "Failed to deserialize user");
                    }

                    // Fetch permissions
                    DocumentSnapshot permDoc = firestore.collection(COLLECTION_USERS)
                            .document(userId)
                            .collection(COLLECTION_USER_PERMISSIONS)
                            .document(ACTIVE_PERMISSIONS_DOC_ID)
                            .get().get();

                    if (permDoc.exists()) {
                        @SuppressWarnings("unchecked")
                        List<String> roles = (List<String>) permDoc.get("roles");
                        @SuppressWarnings("unchecked")
                        List<String> permissions = (List<String>) permDoc.get("permissions");

                        if (roles != null) user.setRoleNames(roles);
                        if (permissions != null) user.setPermissions(permissions);
                    }

                    return user;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(user -> {
                    Set<Roles> roles = new HashSet<>(user.getRoles());
                    Set<Permissions> perms = user.getPermissions().stream()
                            .map(Permissions::valueOf)
                            .collect(Collectors.toSet());

                    return redisCacheService.cacheAllUserData(user, roles, perms).thenReturn(user);
                });
    }

    public Flux<User> findAllUsersByStatus(User.Status status) {
        return Mono.fromCallable(() -> firestore.collection(COLLECTION_USERS)
                        .whereEqualTo("status", status.name())
                        .get())
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        logger.debug("No users found with status [{}]", status);
                        return Flux.empty();
                    }

                    return Flux.fromIterable(querySnapshot.getDocuments())
                            .map(FirestoreUserMapper::documentToUser)
                            .filter(Objects::nonNull);
                })
                .onErrorResume(ex -> {
                    logger.error("Error fetching users by status [{}]: {}", status, ex.getMessage(), ex);
                    return Flux.error(new AuthException("Failed to fetch user list from Firestore",
                            HttpStatus.INTERNAL_SERVER_ERROR));
                });
    }

    public Flux<User> findAllUsers() {
        return Flux.defer(() -> {
                    CollectionReference usersCollection = firestore.collection(COLLECTION_USERS);
                    ApiFuture<QuerySnapshot> future = usersCollection.get();

                    return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                            .flatMapMany(querySnapshot -> {
                                if (querySnapshot.isEmpty()) {
                                    return Flux.empty();
                                }

                                return Flux.fromIterable(querySnapshot.getDocuments())
                                        .mapNotNull(FirestoreUserMapper::documentToUser);
                            })
                            .onErrorResume(e -> {
                                logger.error("❌ Failed to fetch users: {}", e.getMessage(), e);
                                return Flux.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "Failed to retrieve users"));
                            });
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Flux<User> findActiveUsers() {
        return Mono.fromCallable(() -> firestore.collection(COLLECTION_USERS)
                        .whereEqualTo("status", User.Status.ACTIVE.name())
                        .whereEqualTo("enabled", true)
                        .get())
                .flatMap(apiFuture -> Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(apiFuture)))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        return Flux.empty();
                    }

                    List<User> users = FirestoreUserMapper.mapToUsers(
                            new ArrayList<>(querySnapshot.getDocuments()));
                    logger.info("✅ Retrieved {} active users", users.size());
                    return Flux.fromIterable(users);
                })
                .onErrorResume(e -> {
                    logger.error("❌ Error fetching active users: {}", e.getMessage(), e);
                    return Flux.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                            "Failed to retrieve active users"));
                });
    }

    public Flux<PendingUserResponse> getPendingUsersWithApprovalContext(SecurityContext securityContext) {
        logger.info("📋 Fetching pending users - Requester: {} ({})",
                securityContext.getRequesterEmail(), securityContext.getRequesterRole());

        return findAllUsersByStatus(User.Status.PENDING_APPROVAL)
                .map(user -> buildPendingUserResponse(user, securityContext));
    }

    private PendingUserResponse buildPendingUserResponse(User user, SecurityContext securityContext) {
        return PendingUserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles())
                .status(user.getStatus())
                .approvalLevel(user.getApprovalLevel()
                        .orElse(RoleAssignmentService.ApprovalLevel.MANAGER_OR_ABOVE))
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

    // ============================================================================
    // USER UPDATES
    // ============================================================================

    public Mono<User> save(User user) {
        return Mono.defer(() -> {
            Map<String, Object> userData = buildUserUpdateMap(user);

            DocumentReference userRef = firestore.collection(COLLECTION_USERS).document(user.getId());
            ApiFuture<WriteResult> future = userRef.update(userData);

            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .doOnSuccess(result -> logger.info("✅ User {} updated successfully at {}",
                            user.getId(), result.getUpdateTime()))
                    .doOnError(error -> logger.error("❌ User update failed for {}: {}",
                            user.getId(), error.getMessage()))
                    .thenReturn(user);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Void> updateUserInFirestore(User user) {
        return save(user).then();
    }

    public void updateLastLogin(String userId, String ipAddress) {
        Instant lastLoginTimestamp = Instant.now();

        Map<String, Object> updates = Map.of(
                "lastLogin", Timestamp.of(Date.from(lastLoginTimestamp)),
                "lastLoginTimestamp", Timestamp.of(Date.from(lastLoginTimestamp)),
                "lastLoginIp", ipAddress,
                "lastLoginIpAddress", ipAddress
        );

        ApiFuture<WriteResult> future = firestore.collection(COLLECTION_USERS)
                .document(userId).update(updates);

        Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                .doOnSuccess(ignored -> logger.info("✅ Updated last login for user {} from {}",
                        userId, ipAddress))
                .doOnError(e -> logger.error("❌ Error updating last login for {}: {}",
                        userId, e.getMessage()))
                .subscribe();
    }

    private Map<String, Object> buildUserUpdateMap(User user) {
        Map<String, Object> userData = new HashMap<>();
        userData.put("firstName", user.getFirstName());
        userData.put("lastName", user.getLastName());
        userData.put("phoneNumber", user.getPhoneNumber());
        userData.put("department", user.getDepartment());
        userData.put("status", user.getStatus().name());
        userData.put("enabled", user.isEnabled());
        userData.put("accountLocked", user.isAccountLocked());
        userData.put("forcePasswordChange", user.isForcePasswordChange());
        userData.put("roleNames", user.getRoleNames());
        userData.put("permissions", user.getPermissions() != null ?
                user.getPermissions() : Collections.emptyList());
        userData.put("updatedAt", Instant.now());
        return userData;
    }

    // ============================================================================
    // USER DELETION
    // ============================================================================

    public Mono<Void> deleteUser(String userId) {
        if (userId == null) {
            return Mono.error(new IllegalArgumentException("User ID cannot be null"));
        }

        return deleteFromFirebaseAuth(userId)
                .then(deleteFromFirestore(userId));
    }

    private Mono<Void> deleteFromFirebaseAuth(String userId) {
        return Mono.fromCallable(() -> {
                    firebaseAuth.deleteUser(userId);
                    logger.info("🔥 Deleted user from Firebase Auth: {}", userId);
                    return (Void) null;
                }).subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(FirebaseAuthException.class, e -> {
                    if ("USER_NOT_FOUND".equals(e.getAuthErrorCode().name())) {
                        logger.warn("⚠️ User not found in Firebase Auth: {}", userId);
                        return Mono.empty();
                    }
                    logger.error("❌ Firebase Auth deletion failed for {}: {}", userId, e.getMessage());
                    return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                            "Failed to delete user from Firebase Auth"));
                });
    }

    private Mono<Void> deleteFromFirestore(String userId) {
        return Mono.defer(() -> {
            DocumentReference userRef = firestore.collection(COLLECTION_USERS).document(userId);
            ApiFuture<WriteResult> future = userRef.delete();

            return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                    .doOnSuccess(result -> logger.info("✅ Deleted user document from Firestore: {}", userId))
                    .doOnError(error -> logger.error("❌ Failed to delete user from Firestore: {}", userId))
                    .onErrorMap(e -> new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                            "Failed to delete user from Firestore"))
                    .then();
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ============================================================================
    // UTILITY & HELPER METHODS
    // ============================================================================

    public Mono<Boolean> checkEmailAvailability(String email) {
        return Mono.defer(() -> {
            try {
                firebaseAuth.getUserByEmail(email);
                return Mono.just(true); // User exists
            } catch (FirebaseAuthException e) {
                if ("USER_NOT_FOUND".equals(e.getAuthErrorCode().name())) {
                    return Mono.just(false); // Email available
                }
                return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Firebase authentication error: " + e.getMessage()));
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Boolean> existsByEmail(String email) {
        return Mono.fromCallable(() -> firestore.collection(COLLECTION_USERS)
                        .whereEqualTo("email", email)
                        .limit(1)
                        .get())
                .flatMap(future -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(future)))
                .map(snapshot -> !snapshot.isEmpty())
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<String> encryptPassword(String password) {
        return Mono.fromCallable(() -> encryptionService.encrypt(password))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Void> rollbackFirebaseUserCreation(String email) {
        return Mono.fromCallable(() -> {
                    UserRecord userRecord = firebaseAuth.getUserByEmail(email);
                    if (userRecord != null) {
                        firebaseAuth.deleteUser(userRecord.getUid());
                        logger.info("✅ Rolled back Firebase user: {}", email);
                    }
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    public Mono<Void> cleanupFailedRegistration(String email) {
        return Mono.fromCallable(() -> {
            try {
                UserRecord user = firebaseAuth.getUserByEmail(email);
                firebaseAuth.deleteUser(user.getUid());
                logger.info("✅ Cleaned up failed registration for {}", email);
                redisCacheService.removeRegisteredEmail(email).subscribe();
                metricsService.incrementCounter("user.registration.cleanup");
                return null;
            } catch (FirebaseAuthException e) {
                logger.error("❌ Failed to cleanup registration for {}", email, e);
                throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to cleanup registration");
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

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
                .profilePictureUrl(user.getProfilePictureUrl() != null ?
                        user.getProfilePictureUrl() : "")
                .bio(user.getBio() != null ? user.getBio() : "")
                .isPublic(true)
                .build();
    }

    private UserPasswordHistory buildPasswordHistory(User user, String ipAddress) {
        return UserPasswordHistory.builder()
                .userId(user.getId())
                .createdAt(Instant.now())
                .changedByIp(ipAddress)
                .changedByUserAgent(user.getDeviceFingerprint())
                .build();
    }

    // ============================================================================
    // ERROR HANDLING & LOGGING
    // ============================================================================

    private String extractFirebaseRestErrorCode(Map<?, ?> errorBody) {
        try {
            Map<?, ?> error = (Map<?, ?>) errorBody.get("error");
            return (String) ((Map<?, ?>) ((List<?>) error.get("errors")).get(0)).get("message");
        } catch (Exception e) {
            logger.error("⚠️ Failed to extract Firebase error code: {}", e.getMessage());
            return "unknown";
        }
    }

    public Throwable translateFirebaseException(Throwable e) {
        Throwable actual = e.getCause() != null ? e.getCause() : e;

        if (actual instanceof FirebaseAuthException authEx) {
            String errorCode = String.valueOf(authEx.getErrorCode());
            return switch (errorCode) {
                case "USER_NOT_FOUND", "NOT_FOUND", "user-not-found", "invalid-email",
                     "EMAIL_NOT_FOUND", "INVALID_EMAIL" -> AuthException.accountNotFound();
                case "WRONG_PASSWORD", "wrong-password", "INVALID_PASSWORD" ->
                        AuthException.invalidCredentials();
                case "USER_DISABLED", "user-disabled" -> AuthException.accountDisabled();
                case "TOO_MANY_ATTEMPTS_TRY_LATER", "too-many-requests" ->
                        AuthException.rateLimitExceeded();
                case "EMAIL_NOT_VERIFIED" -> AuthException.emailNotVerified();
                default -> new AuthException("Authentication failed: " + errorCode,
                        HttpStatus.UNAUTHORIZED);
            };
        }

        if (actual instanceof FirebaseRestAuthException restEx) {
            String errorCode = restEx.getErrorCode();
            return switch (errorCode) {
                case "EMAIL_NOT_FOUND", "INVALID_EMAIL" -> AuthException.accountNotFound();
                case "INVALID_PASSWORD" -> AuthException.invalidCredentials();
                case "USER_DISABLED" -> AuthException.accountDisabled();
                case "TOO_MANY_ATTEMPTS_TRY_LATER" -> AuthException.rateLimitExceeded();
                default -> new AuthException("Authentication failed: " + errorCode,
                        HttpStatus.UNAUTHORIZED);
            };
        }

        if (actual instanceof BadCredentialsException) {
            return AuthException.invalidCredentials();
        }

        if (actual instanceof DisabledException) {
            return AuthException.accountDisabled();
        }

        logger.error("Unhandled auth exception: {} - {}",
                actual.getClass().getSimpleName(), actual.getMessage());
        return new AuthException("Unexpected error occurred during login",
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    public void logAuthFailure(String email, Throwable error) {
        firestore.collection(COLLECTION_AUTH_LOGS).add(Map.of(
                "email", email,
                "status", ActionType.LOGIN_FAILED,
                "error", error.getMessage(),
                "timestamp", FieldValue.serverTimestamp()
        ));
    }

    public void logAuthSuccess(String email) {
        firestore.collection(COLLECTION_AUTH_LOGS).add(Map.of(
                "email", email,
                "status", ActionType.LOGIN_SUCCESS,
                "timestamp", FieldValue.serverTimestamp()
        ));
    }

    public <T> Mono<T> handleAuthErrors(Mono<T> mono) {
        return mono.onErrorMap(e -> {
            if (e instanceof AuthException) {
                return e;
            }
            return translateFirebaseException(e);
        });
    }

    // ============================================================================
    // GENERIC DOCUMENT OPERATIONS (Consider moving to separate service)
    // ============================================================================

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
                    future.get();
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    public Mono<Void> deleteDocument(String collection, String documentId) {
        logger.warn("🗑️ Deleting Firestore document: {}/{}", collection, documentId);

        DocumentReference docRef = firestore.collection(collection).document(documentId);
        ApiFuture<WriteResult> future = docRef.delete();

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(result -> logger.info("✅ Deleted document: {}/{}",
                        collection, documentId))
                .doOnError(error -> logger.error("❌ Failed to delete {}/{}: {}",
                        collection, documentId, error.getMessage()))
                .onErrorMap(e -> new RuntimeException("Failed to delete Firestore document", e))
                .then();
    }

    // ============================================================================
    // INTERNAL DATA CLASSES
    // ============================================================================

    private static class PermissionData {
        final List<String> roles;
        final List<String> permissions;
        final User.Status status;

        PermissionData(List<String> roles, List<String> permissions, User.Status status) {
            this.roles = roles;
            this.permissions = permissions;
            this.status = status;
        }
    }
}