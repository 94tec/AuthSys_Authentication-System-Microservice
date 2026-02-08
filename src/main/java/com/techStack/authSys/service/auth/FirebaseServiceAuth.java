package com.techStack.authSys.service.auth;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.dto.internal.RequesterContext;
import com.techStack.authSys.dto.internal.SecurityContext;
import com.techStack.authSys.dto.response.PendingUserResponse;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.user.UserApprovalService;
import com.techStack.authSys.service.validation.FirebaseAuthValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Firebase Authentication Service
 *
 * Handles Firebase Auth operations and coordinates with Firestore.
 * This service is deliberately scoped to authentication and persistence,
 * while higher-level registration workflows are orchestrated by UserCreationService.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FirebaseServiceAuth {

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseAuth firebaseAuth;
    private final FirestoreUserRepository userRepository;
    private final UserApprovalService userPermissionWorkflowService;
    private final FirebaseAuthValidator authValidator;
    private final DeviceVerificationService deviceVerificationService;
    private final RoleAssignmentService roleAssignmentService;
    private final Clock clock;

    /* =========================
       Firebase User Creation
       ========================= */

    /**
     * Create Firebase user from evaluated User object.
     * Called AFTER role evaluation by UserCreationService.
     */
    public Mono<User> createFirebaseUser(
            User user,
            String password,
            String ipAddress,
            String deviceFingerprint
    ) {
        Instant now = clock.instant();
        log.info("Creating Firebase user for {} at {}", user.getEmail(), now);

        return createFirebaseAuthUser(user.getEmail(), password, user.getPhoneNumber(), false)
                .flatMap(userRecord -> {
                    user.setId(userRecord.getUid());
                    log.info("✅ Firebase user created with UID: {} at {}", userRecord.getUid(), now);
                    return saveUserAtomic(user, ipAddress, deviceFingerprint);
                })
                .doOnError(e -> log.error("❌ Failed to create Firebase user for {} at {}: {}",
                        user.getEmail(), now, e.getMessage()));
    }

    /**
     * Create Super Admin (standalone method for initial setup).
     * This bypasses approval workflows and grants immediate full permissions.
     */
    public Mono<User> createSuperAdmin(
            User user,
            String password,
            String ipAddress,
            String deviceFingerprint
    ) {
        Instant now = clock.instant();
        log.info("🔐 Creating Super Admin: {} at {}", user.getEmail(), now);

        return createFirebaseAuthUser(user.getEmail(), password, user.getPhoneNumber(), true)
                .flatMap(userRecord -> {
                    user.setId(userRecord.getUid());
                    return saveUserAtomic(user, ipAddress, deviceFingerprint);
                })
                .doOnSuccess(u -> log.info("✅ Super Admin created: {} at {}", u.getEmail(), now))
                .doOnError(e -> log.error("❌ Super Admin creation failed at {}: {}", now, e.getMessage()));
    }

    /* =========================
       Atomic Save
       ========================= */

    /**
     * Save user atomically to Firestore with permissions and device fingerprint.
     */
    private Mono<User> saveUserAtomic(User user, String ipAddress, String deviceFingerprint) {
        Instant now = clock.instant();

        return userPermissionWorkflowService.preparePermissionData(user)
                .flatMap(permData -> userRepository.saveUserAtomic(user, ipAddress, deviceFingerprint, permData))
                .flatMap(savedUser -> deviceVerificationService.saveUserFingerprint(savedUser.getId(), deviceFingerprint)
                        .thenReturn(savedUser))
                .doOnSuccess(savedUser -> log.info("✅ User saved to Firestore: {} at {}", savedUser.getId(), now))
                .doOnError(e -> log.error("❌ Failed to save user to Firestore at {}: {}", now, e.getMessage()));
    }

    /* =========================
       Authentication
       ========================= */

    /**
     * Validate user credentials
     */
    public Mono<Void> validateCredentials(String email, String password) {
        Instant now = clock.instant();

        return authValidator.validateCredentials(email, password)
                .doOnSuccess(v -> log.info("🔓 Credentials validated for: {} at {}", email, now))
                .doOnError(e -> log.warn("🔒 Validation failed for: {} at {}", email, now));
    }

    /**
     * Get Firebase UserRecord by email
     */
    public Mono<UserRecord> getUserRecord(String email) {
        return authValidator.getUserRecord(email);
    }

    /* =========================
       User Retrieval
       ========================= */

    /**
     * Find user by email
     */
    public Mono<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * Get user by ID
     */
    public Mono<User> getUserById(String userId) {
        return userRepository.findById(userId);
    }

    /**
     * Fetch user with complete permissions
     */
    public Mono<User> fetchUserDetailsWithPermissions(String userId) {
        return userRepository.fetchUserWithPermissions(userId);
    }

    /**
     * Find all users
     */
    public Flux<User> findAllUsers() {
        return userRepository.findAll();
    }

    /**
     * Find active users only
     */
    public Flux<User> findActiveUsers() {
        return userRepository.findByStatus(UserStatus.ACTIVE)
                .filter(User::isEnabled);
    }

    /**
     * Find users by status
     */
    public Flux<User> findAllUsersByStatus(UserStatus status) {
        return userRepository.findByStatus(status);
    }

    /**
     * Get pending users with approval context
     */
    public Flux<PendingUserResponse> getPendingUsersWithApprovalContext(SecurityContext securityContext) {
        Instant now = clock.instant();

        log.info("📋 Fetching pending users - Requester: {} at {}",
                securityContext.getRequesterEmail(), now);

        return findAllUsersByStatus(UserStatus.PENDING_APPROVAL)
                .map(user -> buildPendingUserResponse(user, securityContext));
    }

    /* =========================
       User Updates
       ========================= */

    /**
     * Save user
     */
    public Mono<User> save(User user) {
        return userRepository.save(user);
    }

    /**
     * Update user in Firestore
     */
    public Mono<Void> updateUserInFirestore(User user) {
        return userRepository.update(user);
    }

    /**
     * Update last login timestamp
     */
    public Mono<Void> updateLastLogin(String userId, String ipAddress) {
        Instant now = clock.instant();

        return userRepository.updateLastLogin(userId, ipAddress)
                .doOnSuccess(v -> log.debug("Updated last login for {} at {}", userId, now));
    }

    /* =========================
       Permission Management
       ========================= */

    /**
     * Approve user and grant permissions
     */
    public Mono<Void> approveUserAndGrantPermissions(String userId, String approvedBy) {
        Instant now = clock.instant();

        return getUserById(userId)
                .flatMap(user -> userPermissionWorkflowService.approveAndGrantPermissions(user, approvedBy))
                .doOnSuccess(v -> log.info("✅ User approved: {} at {}", userId, now))
                .doOnError(e -> log.error("❌ Approval failed for {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /**
     * Get user permissions
     */
    public Mono<Map<String, Object>> getUserPermissions(String userId) {
        return userPermissionWorkflowService.getActivePermissions(userId);
    }

    /* =========================
       User Deletion
       ========================= */

    /**
     * Delete user from Firebase and Firestore
     */
    public Mono<Void> deleteUser(String userId) {
        Instant now = clock.instant();

        if (userId == null) {
            return Mono.error(new IllegalArgumentException("User ID cannot be null"));
        }

        return deleteFromFirebaseAuth(userId)
                .then(userRepository.delete(userId))
                .doOnSuccess(v -> log.info("🗑️ User deleted: {} at {}", userId, now))
                .doOnError(e -> log.error("❌ Deletion failed for {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Check if email is available (returns true if user exists)
     */
    public Mono<Boolean> checkEmailAvailability(String email) {
        return Mono.fromCallable(() -> {
                    try {
                        firebaseAuth.getUserByEmail(email);
                        return true; // User exists
                    } catch (FirebaseAuthException e) {
                        if ("USER_NOT_FOUND".equals(e.getAuthErrorCode().name())) {
                            return false; // Email available
                        }
                        throw e;
                    }
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Check if user exists by email
     */
    public Mono<Boolean> existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    /**
     * Cleanup failed registration
     */
    public Mono<Void> cleanupFailedRegistration(String email) {
        Instant now = clock.instant();

        return rollbackFirebaseUser(email)
                .doOnSuccess(v -> log.info("✅ Cleaned up failed registration: {} at {}",
                        email, now));
    }

    /* =========================
       Private Helpers
       ========================= */

    /**
     * Create Firebase Auth user
     */
    private Mono<UserRecord> createFirebaseAuthUser(
            String email,
            String password,
            String phoneNumber,
            boolean emailVerified
    ) {
        return Mono.fromCallable(() -> {
            UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                    .setEmail(email)
                    .setPassword(password)
                    .setEmailVerified(emailVerified)
                    .setDisabled(false);

            if (phoneNumber != null && !phoneNumber.isBlank()) {
                request.setPhoneNumber(phoneNumber);
            }

            return firebaseAuth.createUser(request);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Delete user from Firebase Auth
     */
    private Mono<Void> deleteFromFirebaseAuth(String userId) {
        return Mono.fromCallable(() -> {
                    firebaseAuth.deleteUser(userId);
                    log.info("🔥 Deleted from Firebase Auth: {}", userId);
                    return (Void) null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(FirebaseAuthException.class, e -> {
                    if ("USER_NOT_FOUND".equals(e.getAuthErrorCode().name())) {
                        log.warn("⚠️ User not found in Firebase Auth: {}", userId);
                        return Mono.empty();
                    }
                    return Mono.error(e);
                });
    }

    /**
     * Rollback Firebase user creation on error
     */
    public Mono<Void> rollbackFirebaseUser(String email) {
        return Mono.fromCallable(() -> {
                    try {
                        UserRecord userRecord = firebaseAuth.getUserByEmail(email);
                        if (userRecord != null) {
                            firebaseAuth.deleteUser(userRecord.getUid());
                            log.info("♻️ Rolled back Firebase user: {}", email);
                        }
                    } catch (FirebaseAuthException e) {
                        log.warn("⚠️ Rollback failed for {}: {}", email, e.getMessage());
                    }
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Build pending user response DTO
     */
    private PendingUserResponse buildPendingUserResponse(User user, SecurityContext securityContext) {
        Instant now = clock.instant();

        return PendingUserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles())
                .status(user.getStatus())
                .approvalLevel(user.getApprovalLevel())
                .createdAt(user.getCreatedAt() != null ? user.getCreatedAt() : now)
                .department(user.getDepartment() != null ? user.getDepartment() : "")
                .canApprove(roleAssignmentService.canApproveUser(securityContext, user))
                .requesterContext(buildRequesterContext(securityContext, now))
                .build();
    }

    /**
     * Build requester context
     */
    private RequesterContext buildRequesterContext(SecurityContext securityContext, Instant timestamp) {
        return RequesterContext.builder()
                .requesterEmail(securityContext.getRequesterEmail())
                .requesterRole(securityContext.getRequesterRole())
                .timestamp(timestamp)
                .build();
    }
}