package com.techStack.authSys.models.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.cloud.firestore.annotation.DocumentId;
import com.google.cloud.firestore.annotation.PropertyName;
import com.google.cloud.spring.data.firestore.Document;
import lombok.*;

import java.time.Instant;
import java.util.*;

/**
 * Firestore persistence model.
 *
 * Owns: identity detail, roles, permissions, security state,
 *       approval workflow, password management, MFA.
 *
 * Firestore type rules strictly followed:
 *   ✅ String, boolean, int, long, Instant
 *   ✅ List<String>, Map<String, String>
 *   ✅ Nested POJOs with no-arg constructors (SecuritySnapshot, PasswordSnapshot)
 *   ❌ Set — use List with manual dedup
 *   ❌ Map<String, Object> — use Map<String, String>
 *   ❌ Complex objects with inner classes (SecurityMetadata) — use snapshot POJOs
 *
 * Document ID = Firebase Auth UID.
 */
@Document(collectionName = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDocument {

    // =========================================================================
    // IDENTITY
    // =========================================================================

    @DocumentId
    private String id;                          // = Firebase Auth UID

    private String email;
    private String firstName;
    private String lastName;
    private String username;
    private String identityNo;
    private String phoneNumber;
    private String profilePictureUrl;
    private String bio;
    private String userProfileId;
    private String department;

    // =========================================================================
    // ROLES & PERMISSIONS
    // =========================================================================

    @PropertyName("roles")
    @Builder.Default
    private List<String> roleNames = new ArrayList<>();

    /**
     * Direct permission grants on this user beyond role defaults.
     * Format: "portfolio:publish", "order:view_all"
     */
    @PropertyName("permissions")
    @Builder.Default
    private List<String> additionalPermissions = new ArrayList<>();

    /**
     * Custom permission overrides (fine-grained user-level grants).
     */
    @Builder.Default
    private List<String> customPermissions = new ArrayList<>();

    /**
     * Roles requested during registration.
     */
    @PropertyName("requested_roles")
    @Builder.Default
    private List<String> requestedRoleNames = new ArrayList<>();

    /**
     * ABAC attributes — key/value metadata for attribute-based checks.
     * Map<String,String> only — Firestore requirement.
     * Keys follow "namespace:key" convention e.g. "access:level".
     */
    @Builder.Default
    private Map<String, String> attributes = new HashMap<>();

    // =========================================================================
    // ACCOUNT STATUS
    // =========================================================================

    @PropertyName("status")
    private String status;                      // UserStatus.name()

    @PropertyName("enabled")
    @Builder.Default
    private boolean enabled = false;

    @PropertyName("account_locked")
    @Builder.Default
    private boolean accountLocked = false;

    @PropertyName("account_disabled")
    @Builder.Default
    private boolean accountDisabled = false;

    @PropertyName("email_verified")
    @Builder.Default
    private boolean emailVerified = false;

    @PropertyName("phone_verified")
    @Builder.Default
    private boolean phoneVerified = false;

    @PropertyName("force_password_change")
    @Builder.Default
    private boolean forcePasswordChange = false;

    // =========================================================================
    // APPROVAL WORKFLOW
    // =========================================================================

    @PropertyName("approval_level")
    private String approvalLevel;               // ApprovalLevel.name()

    @PropertyName("approved_at")
    private Instant approvedAt;

    @PropertyName("approved_by")
    private String approvedBy;

    @PropertyName("rejected_at")
    private Instant rejectedAt;

    @PropertyName("rejected_by")
    private String rejectedBy;

    @PropertyName("rejection_reason")
    private String rejectionReason;

    // =========================================================================
    // SECURITY STATE — flat fields only, no SecurityMetadata object
    // SecurityMetadata's inner classes are not Firestore-safe.
    // The relevant fields are inlined here as primitives/Strings.
    // =========================================================================

    @PropertyName("failed_login_attempts")
    @Builder.Default
    private int failedLoginAttempts = 0;

    @PropertyName("login_attempts")
    @Builder.Default
    private int loginAttempts = 0;

    @PropertyName("last_login")
    private Instant lastLogin;

    @PropertyName("last_login_ip")
    private String lastLoginIp;

    @PropertyName("last_login_user_agent")
    private String lastLoginUserAgent;

    @PropertyName("last_login_country")
    private String lastLoginCountry;

    @PropertyName("last_login_city")
    private String lastLoginCity;

    @PropertyName("last_login_device_id")
    private String lastLoginDeviceId;

    @PropertyName("account_locked_until")
    private Instant accountLockedUntil;

    @PropertyName("lock_reason")
    private String lockReason;

    @PropertyName("lock_type")
    private String lockType;                    // SecurityMetadata.LockType.name()

    @PropertyName("risk_score")
    @Builder.Default
    private int riskScore = 0;

    @PropertyName("risk_level")
    private String riskLevel;                   // SecurityMetadata.RiskLevel.name()

    @PropertyName("risk_explanation")
    private String riskExplanation;

    @PropertyName("risk_score_updated_at")
    private Instant riskScoreUpdatedAt;

    /**
     * Known device fingerprints — List<String> (Firestore requires List, not Set).
     */
    @PropertyName("known_device_fingerprints")
    @Builder.Default
    private List<String> knownDeviceFingerprints = new ArrayList<>();

    // =========================================================================
    // MFA
    // =========================================================================

    @PropertyName("mfa_enabled")
    @Builder.Default
    private boolean mfaEnabled = false;

    @PropertyName("mfa_required")
    @Builder.Default
    private boolean mfaRequired = false;

    @JsonIgnore
    @PropertyName("otp_secret")
    private String otpSecret;

    // =========================================================================
    // PASSWORD MANAGEMENT
    // =========================================================================

    @PropertyName("password_last_changed")
    private Instant passwordLastChanged;

    @PropertyName("password_expires_at")
    private Instant passwordExpiresAt;

    @PropertyName("password_compromised")
    @Builder.Default
    private boolean passwordCompromised = false;

    @PropertyName("compromise_source")
    private String compromiseSource;

    @PropertyName("first_time_setup_completed")
    @Builder.Default
    private boolean firstTimeSetupCompleted = false;

    @PropertyName("first_time_setup_completed_at")
    private Instant firstTimeSetupCompletedAt;

    @PropertyName("temporary_password_locked")
    @Builder.Default
    private boolean temporaryPasswordLocked = false;

    @PropertyName("temporary_password_locked_at")
    private Instant temporaryPasswordLockedAt;

    @JsonIgnore
    @PropertyName("password_reset_token_hash")
    private String passwordResetTokenHash;

    @JsonIgnore
    @PropertyName("password_reset_token_expires_at")
    private Instant passwordResetTokenExpiresAt;

    /**
     * Password history — stored as List of Maps.
     * Each entry: {hash, algorithm, changedAt, changedFromIp, reason}
     * Using Map<String,String> so Firestore can serialize it.
     */
    @PropertyName("password_history")
    @Builder.Default
    private List<Map<String, String>> passwordHistory = new ArrayList<>();

    // =========================================================================
    // EMAIL VERIFICATION
    // =========================================================================

    @JsonIgnore
    @PropertyName("verification_token_hash")
    private String verificationTokenHash;

    @JsonIgnore
    @PropertyName("verification_token_expires_at")
    private Instant verificationTokenExpiresAt;

    // =========================================================================
    // AUDIT
    // =========================================================================

    @PropertyName("created_at")
    private Instant createdAt;

    @PropertyName("created_by")
    private String createdBy;

    @PropertyName("updated_at")
    private Instant updatedAt;

    // =========================================================================
    // CONVENIENCE METHODS
    // =========================================================================

    public void addRole(String roleName) {
        if (roleNames == null) roleNames = new ArrayList<>();
        if (!roleNames.contains(roleName)) roleNames.add(roleName);
    }

    public void removeRole(String roleName) {
        if (roleNames != null) roleNames.remove(roleName);
    }

    public boolean hasRole(String roleName) {
        return roleNames != null && roleNames.contains(roleName);
    }

    public void addPermission(String permission) {
        if (additionalPermissions == null) additionalPermissions = new ArrayList<>();
        if (!additionalPermissions.contains(permission)) additionalPermissions.add(permission);
    }

    public void addCustomPermission(String permission) {
        if (customPermissions == null) customPermissions = new ArrayList<>();
        if (!customPermissions.contains(permission)) customPermissions.add(permission);
    }

    public void setAttribute(String key, String value) {
        if (attributes == null) attributes = new HashMap<>();
        attributes.put(key, value);
    }

    public String getAttribute(String key) {
        return attributes != null ? attributes.get(key) : null;
    }

    public void registerDevice(String fingerprint, int maxDevices) {
        if (knownDeviceFingerprints == null) knownDeviceFingerprints = new ArrayList<>();
        if (!knownDeviceFingerprints.contains(fingerprint)) {
            knownDeviceFingerprints.add(fingerprint);
        }
        while (knownDeviceFingerprints.size() > maxDevices) {
            knownDeviceFingerprints.remove(0);
        }
    }

    public boolean isKnownDevice(String fingerprint) {
        return knownDeviceFingerprints != null
            && knownDeviceFingerprints.contains(fingerprint);
    }

    public UserStatus getUserStatus() {
        return status != null
            ? UserStatus.valueOf(status)
            : UserStatus.PENDING_APPROVAL;
    }

    public void setUserStatus(UserStatus userStatus) {
        this.status = userStatus != null ? userStatus.name() : null;
    }

    public ApprovalLevel getApprovalLevelEnum() {
        return approvalLevel != null
            ? ApprovalLevel.valueOf(approvalLevel)
            : null;
    }

    public void setApprovalLevelEnum(ApprovalLevel level) {
        this.approvalLevel = level != null ? level.name() : null;
    }

    public void approve(String approvedBy, Instant now) {
        setUserStatus(UserStatus.ACTIVE);
        this.enabled     = true;
        this.approvedAt  = now;
        this.approvedBy  = approvedBy;
        setApprovalLevelEnum(ApprovalLevel.APPROVED);
        this.updatedAt   = now;
    }

    public void reject(String rejectedBy, String reason, Instant now) {
        setUserStatus(UserStatus.REJECTED);
        this.enabled         = false;
        this.rejectedAt      = now;
        this.rejectedBy      = rejectedBy;
        this.rejectionReason = reason;
        setApprovalLevelEnum(ApprovalLevel.REJECTED);
        this.updatedAt       = now;
    }

    public void recordLogin(String ip, String userAgent,
                             String deviceId, String country,
                             String city, Instant now) {
        this.lastLogin          = now;
        this.lastLoginIp        = ip;
        this.lastLoginUserAgent = userAgent;
        this.lastLoginDeviceId  = deviceId;
        this.lastLoginCountry   = country;
        this.lastLoginCity      = city;
        this.loginAttempts++;
        this.failedLoginAttempts = 0;
        this.updatedAt           = now;
    }

    public void recordFailedLogin(Instant now) {
        this.failedLoginAttempts++;
        this.updatedAt = now;
    }

    public boolean isActive() {
        return UserStatus.ACTIVE.name().equals(status)
            && enabled && !accountLocked && !accountDisabled;
    }

    public boolean isPasswordExpired(java.time.Clock clock) {
        return passwordExpiresAt != null
            && clock.instant().isAfter(passwordExpiresAt);
    }

    /**
     * Creates a default document for a brand new user.
     * Assigned USER role, pending approval.
     */
    public static UserDocument defaultFor(String firebaseUid,
                                           String email,
                                           String firstName,
                                           String lastName,
                                           Instant now) {
        return UserDocument.builder()
            .id(firebaseUid)
            .email(email)
            .firstName(firstName)
            .lastName(lastName)
            .roleNames(new ArrayList<>(List.of("USER")))
            .status(UserStatus.PENDING_APPROVAL.name())
            .approvalLevel(ApprovalLevel.PENDING_L1.name())
            .enabled(false)
            .createdAt(now)
            .updatedAt(now)
            .build();
    }

    @Override
    public String toString() {
        return String.format("UserDocument[id=%s, email=%s, status=%s, roles=%s]",
            id, email, status, roleNames);
    }
}