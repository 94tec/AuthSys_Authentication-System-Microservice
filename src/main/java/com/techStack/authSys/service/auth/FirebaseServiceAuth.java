package com.techStack.authSys.service.auth;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.dto.internal.RequesterContext;
import com.techStack.authSys.dto.internal.SecurityContext;
import com.techStack.authSys.dto.response.PendingUserResponse;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.models.audit.AuditEntry;
import com.techStack.authSys.models.user.PermissionData;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.user.AdminService;
import com.techStack.authSys.service.validation.FirebaseAuthValidator;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Firebase Authentication Service
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
    private final FirebaseAuthValidator authValidator;
    private final DeviceVerificationService deviceVerificationService;
    private final PermissionProvider permissionProvider;
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
            String deviceFingerprint) {

        Instant now = clock.instant();
        log.info("Creating Firebase user for {} at {}", user.getEmail(), now);

        return createFirebaseAuthUser(user.getEmail(), password, user.getPhoneNumber(), false)
                .flatMap(userRecord -> {
                    user.setId(userRecord.getUid());
                    log.info("✅ Firebase Auth user created UID: {} at {}", userRecord.getUid(), now);
                    return saveUserAtomic(user, ipAddress, deviceFingerprint);
                })
                .doOnError(e -> log.error("❌ Failed to create Firebase user for {} at {}: {}",
                        user.getEmail(), now, e.getMessage()));
    }

    /**
     * Create Super Admin — bypasses approval workflows, grants immediate full permissions.
     * Called by TransactionalBootstrapService.
     */
    public Mono<User> createSuperAdmin(
            User user,
            String password,
            String ipAddress,
            String deviceFingerprint) {

        Instant now = clock.instant();
        log.info("🔐 Creating Super Admin: {} at {}", user.getEmail(), now);

        return createFirebaseAuthUser(user.getEmail(), password, user.getPhoneNumber(), true)
                .flatMap(userRecord -> {
                    user.setId(userRecord.getUid()); // UID set HERE before Firestore save
                    return saveUserAtomic(user, ipAddress, deviceFingerprint);
                })
                .doOnSuccess(u -> log.info("✅ Super Admin created UID: {} at {}", u.getId(), now))
                .doOnError(e -> log.error("❌ Super Admin creation failed at {}: {}",
                        now, e.getMessage()));
    }

    /**
     * Save user atomically with permissions
     *
     * @param user User to save
     * @param ipAddress IP address for audit
     * @param deviceFingerprint Device fingerprint
     * @return Saved user
     */
    private Mono<User> saveUserAtomic(
            User user,
            String ipAddress,
            String deviceFingerprint) {

        Instant now = clock.instant();
        String approverId = getCurrentUserId(); // Implement this to get from security context

        log.info("💾 Saving user {} atomically at {}", user.getId(), now);

        return Mono.fromCallable(() -> permissionProvider.resolveEffectivePermissions(user))
                .switchIfEmpty(Mono.just(Collections.emptySet()))
                .flatMap(permissions -> {
                    log.debug("📦 Got {} permissions for user, preparing permission data...",
                            permissions.size());

                    try {
                        PermissionData permissionData = preparePermissionData(
                                user,
                                permissions,
                                approverId,
                                now
                        );

                        log.debug("📦 Permission data prepared, saving to Firestore...");

                        return userRepository.saveUserAtomic(
                                user,
                                ipAddress,
                                deviceFingerprint,
                                permissionData
                        );
                    } catch (Exception e) {
                        log.error("❌ Failed to prepare permission data: {}", e.getMessage());
                        return Mono.error(e);
                    }
                })
                .flatMap(savedUser -> {
                    log.debug("🔐 Saving device fingerprint for user: {}", savedUser.getId());

                    return deviceVerificationService.saveUserFingerprint(
                                    savedUser.getId(),
                                    deviceFingerprint
                            )
                            .thenReturn(savedUser)
                            .onErrorResume(e -> {
                                log.error("⚠️ Failed to save device fingerprint, but user was created: {}",
                                        e.getMessage());
                                return Mono.just(savedUser); // Don't fail the whole operation
                            });
                })
                .doOnSuccess(saved ->
                        log.info("✅ User saved to Firestore UID: {} at {}",
                                saved.getId(), now))
                .doOnError(e ->
                        log.error("❌ Failed to save user to Firestore at {}: {}",
                                now, e.getMessage(), e));
    }
    /**
     * Prepare permission data for storage
     */
    private PermissionData preparePermissionData(
            User user,
            Set<String> permissions,
            String approverId,
            Instant now) {

        log.debug("📦 Preparing permission data for user: {}", user.getId());

        return PermissionData.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .roles(new ArrayList<>(user.getRoleNames()))
                .permissions(new ArrayList<>(permissions))
                .status(user.getStatus() != null
                        ? user.getStatus()
                        : UserStatus.PENDING_APPROVAL)
                .approvedBy(approverId)
                .approvedAt(now)
                .grantedAt(now)
                .version(1)
                .active(true)
                .permissionMetadata(Map.of(
                        "source",           "role-based",
                        "resolvedAt",       now.toString(),
                        "totalPermissions", String.valueOf(permissions.size())
                ))
                // ← CHANGED: typed AuditEntry instead of Map<String, String>
                .auditTrail(new ArrayList<>(List.of(
                        AuditEntry.userCreated(approverId, now)
                )))
                .build();
    }


    /**
     * Get current user ID from security context
     */
    private String getCurrentUserId() {
        // Implement this based on your security context
        // Example with Spring Security:
        // Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // return auth != null ? auth.getName() : "SYSTEM";
        return "SYSTEM"; // Default fallback
    }

    /* =========================
       Authentication
       ========================= */

    public Mono<Void> validateCredentials(String email, String password) {
        return authValidator.validateCredentials(email, password)
                .doOnSuccess(v -> log.info("🔓 Credentials validated: {}", HelperUtils.maskEmail(email)))
                .doOnError(e -> log.warn("🔒 Validation failed: {}", HelperUtils.maskEmail(email)));
    }

    public Mono<UserRecord> getUserRecord(String email) {
        return authValidator.getUserRecord(email);
    }

    /* =========================
       User Retrieval
       ========================= */

    public Mono<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Mono<User> getUserById(String userId) {
        return userRepository.findById(userId);
    }

    public Mono<User> fetchUserDetailsWithPermissions(String userId) {
        return userRepository.fetchUserWithPermissions(userId);
    }

    public Flux<User> findAllUsers() {
        return userRepository.findAll();
    }

    public Flux<User> findActiveUsers() {
        return userRepository.findByStatus(UserStatus.ACTIVE).filter(User::isEnabled);
    }

    public Flux<User> findAllUsersByStatus(UserStatus status) {
        return userRepository.findByStatus(status);
    }

    public Flux<PendingUserResponse> getPendingUsersWithApprovalContext(
            SecurityContext securityContext) {
        return findAllUsersByStatus(UserStatus.PENDING_APPROVAL)
                .map(user -> buildPendingUserResponse(user, securityContext));
    }

    /* =========================
       User Updates
       ========================= */

    public Mono<User> save(User user) {
        return userRepository.save(user);
    }

    public Mono<Void> updateUserInFirestore(User user) {
        return userRepository.update(user);
    }

    public Mono<Void> updateLastLogin(String userId, String ipAddress) {
        return userRepository.updateLastLogin(userId, ipAddress)
                .doOnSuccess(v -> log.debug("Updated last login for {}", userId));
    }

    /* =========================
       User Deletion
       ========================= */

    public Mono<Void> deleteUser(String userId) {
        if (userId == null) {
            return Mono.error(new IllegalArgumentException("User ID cannot be null"));
        }
        return deleteFromFirebaseAuth(userId)
                .then(userRepository.delete(userId))
                .doOnSuccess(v -> log.info("🗑️ User deleted: {}", userId));
    }

    /* =========================
       Email Existence Checks
       ========================= */

    /**
     * Check if a user exists in Firebase Auth by email.
     *
     * Returns: true  = user EXISTS in Firebase Auth (email is taken)
     *          false = user does NOT exist (email is available)
     *
     * Called by DuplicateEmailCheckService which treats true = "already registered".
     *
     * ✅ FIXED: Non-USER_NOT_FOUND errors (network, quota, etc.) now propagate
     * as Mono.error() so DuplicateEmailCheckService can log and handle them
     * appropriately, rather than silently returning false and allowing duplicates.
     */
    public Mono<Boolean> checkEmailAvailability(String email) {
        return Mono.fromCallable(() -> {
                    try {
                        firebaseAuth.getUserByEmail(email);
                        return true; // User found → email is taken
                    } catch (FirebaseAuthException e) {
                        String code = e.getAuthErrorCode() != null
                                ? e.getAuthErrorCode().name() : "";
                        if ("USER_NOT_FOUND".equals(code)) {
                            return false; // Email is available
                        }
                        // Rethrow — network/quota/auth errors should not silently pass
                        throw e;
                    }
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Check if a user exists in Firestore by email.
     * Used by bootstrap and TransactionalBootstrapService.existsByEmail().
     */
    public Mono<Boolean> existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    /* =========================
       Cleanup / Rollback
       ========================= */

    public Mono<Void> cleanupFailedRegistration(String email) {
        return rollbackFirebaseUser(email)
                .doOnSuccess(v -> log.info("✅ Cleaned up failed registration: {}", email));
    }

    public Mono<Void> rollbackFirebaseUser(String email) {
        return Mono.fromCallable(() -> {
                    try {
                        UserRecord record = firebaseAuth.getUserByEmail(email);
                        if (record != null) {
                            firebaseAuth.deleteUser(record.getUid());
                            log.info("♻️ Rolled back Firebase user: {}", HelperUtils.maskEmail(email));
                        }
                    } catch (FirebaseAuthException e) {
                        log.warn("⚠️ Rollback skipped for {} (may not exist): {}", HelperUtils.maskEmail(email), e.getMessage());
                    }
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /* =========================
       Private Helpers
       ========================= */

    private Mono<UserRecord> createFirebaseAuthUser(
            String email, String password, String phoneNumber, boolean emailVerified) {

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

    private Mono<Void> deleteFromFirebaseAuth(String userId) {
        return Mono.fromRunnable(() -> {
                    try {
                        firebaseAuth.deleteUser(userId);
                        log.info("🔥 Deleted from Firebase Auth: {}", userId);
                    } catch (FirebaseAuthException e) {
                        throw new RuntimeException(e);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    Throwable cause = e.getCause();

                    if (cause instanceof FirebaseAuthException fae) {
                        String code = fae.getAuthErrorCode() != null
                                ? fae.getAuthErrorCode().name()
                                : "";

                        if ("USER_NOT_FOUND".equals(code)) {
                            log.warn("⚠️ User not found in Firebase Auth (already deleted?): {}", userId);
                            return Mono.empty();
                        }

                        return Mono.error(fae);
                    }

                    return Mono.error(e);
                }).then();
    }


    private PendingUserResponse buildPendingUserResponse(
            User user, SecurityContext securityContext) {
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

    private RequesterContext buildRequesterContext(
            SecurityContext securityContext, Instant timestamp) {
        return RequesterContext.builder()
                .requesterEmail(securityContext.getRequesterEmail())
                .requesterRole(securityContext.getRequesterRole())
                .timestamp(timestamp)
                .build();
    }
}