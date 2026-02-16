package com.techStack.authSys.models.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.cloud.firestore.annotation.DocumentId;
import com.google.cloud.firestore.annotation.PropertyName;
import com.google.cloud.spring.data.firestore.Document;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.security.SecurityMetadata;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * User Domain Model
 *
 * Pure domain model - accepts Instant for all timestamps.
 * Clock handling is done in the service layer.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Document(collectionName = "users")
public class User implements UserDetails {

    // ==========================================
    // CORE IDENTITY
    // ==========================================

    @DocumentId
    private String id;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "First name is required")
    @Size(max = 50)
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(max = 50)
    private String lastName;

    @Size(max = 50)
    private String username;

    private String identityNo;
    private String phoneNumber;

    @JsonIgnore
    private transient String password;

    // ==========================================
    // ROLES & PERMISSIONS
    // ==========================================

    @PropertyName("roles")
    private List<String> roleNames = new ArrayList<>();

    @PropertyName("permissions")
    private List<String> additionalPermissions = new ArrayList<>();

    private Set<Roles> requestedRoles;

    private String department;

    private Map<String, Object> attributes = new HashMap<>();

    // ==========================================
    // ACCOUNT STATUS & STATE
    // ==========================================

    @PropertyName("status")
    private UserStatus status = UserStatus.PENDING_APPROVAL;

    @PropertyName("enabled")
    private boolean enabled = false;

    @PropertyName("account_locked")
    private boolean accountLocked = false;

    @PropertyName("account_disabled")
    private boolean accountDisabled = false;

    @PropertyName("email_verified")
    private boolean emailVerified = false;

    @PropertyName("force_password_change")
    private boolean forcePasswordChange = false;

    private boolean phoneVerified = false;

    // ==========================================
    // SECURITY & AUTHENTICATION
    // ==========================================

    @PropertyName("security_metadata")
    private SecurityMetadata securityMetadata;

    @JsonIgnore
    @PropertyName("password_history")
    private List<UserPasswordHistory> passwordHistoryEntries = new ArrayList<>();

    @PropertyName("mfa_enabled")
    private boolean mfaEnabled = false;

    @PropertyName("mfa_required")
    private boolean mfaRequired = false;

    @JsonIgnore
    @PropertyName("otp_secret")
    private String otpSecret;

    @PropertyName("login_attempts")
    private int loginAttempts = 0;

    @PropertyName("failed_login_attempts")
    private int failedLoginAttempts = 0;

    @PropertyName("last_login")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant lastLogin;

    @PropertyName("last_login_ip")
    private String lastLoginIp;

    @PropertyName("last_login_user_agent")
    private String lastLoginUserAgent;

    @PropertyName("known_device_fingerprints")
    private String knownDeviceFingerprints = "";

    // ==========================================
    // PASSWORD MANAGEMENT
    // ==========================================

    @PropertyName("password_last_changed")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant passwordLastChanged;

    @PropertyName("password_expires_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant passwordExpiresAt;

    // First-time setup fields (ADD THESE)
    private boolean firstTimeSetupCompleted;
    private Instant firstTimeSetupCompletedAt;

    // Temporary password lock fields (ADD THESE if not present)
    private boolean temporaryPasswordLocked;
    private Instant temporaryPasswordLockedAt;

    @JsonIgnore
    @PropertyName("password_reset_token_hash")
    private String passwordResetTokenHash;

    @JsonIgnore
    @PropertyName("password_reset_token_expires_at")
    private Instant passwordResetTokenExpiresAt;

    // ==========================================
    // EMAIL VERIFICATION
    // ==========================================

    @JsonIgnore
    @PropertyName("verification_token_hash")
    private String verificationTokenHash;

    @JsonIgnore
    @PropertyName("verification_token_expires_at")
    private Instant verificationTokenExpiresAt;

    // ==========================================
    // APPROVAL WORKFLOW
    // ==========================================

    @PropertyName("approval_level")
    private ApprovalLevel approvalLevel;

    @PropertyName("approved_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant approvedAt;

    @PropertyName("approved_by")
    private String approvedBy;

    @PropertyName("rejected_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant rejectedAt;

    @PropertyName("rejected_by")
    private String rejectedBy;

    @PropertyName("rejection_reason")
    private String rejectionReason;

    // ==========================================
    // PROFILE INFORMATION
    // ==========================================

    @PropertyName("profile_picture_url")
    private String profilePictureUrl;

    @PropertyName("bio")
    @Size(max = 500)
    private String bio;

    @PropertyName("user_profile_id")
    private String userProfileId;

    // ==========================================
    // AUDIT FIELDS
    // ==========================================

    @PropertyName("created_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant createdAt;

    @PropertyName("created_by")
    private String createdBy;

    @PropertyName("updated_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant updatedAt;

    // ==========================================
    // SPRING SECURITY INTEGRATION
    // ==========================================

    @JsonIgnore
    private transient Collection<? extends GrantedAuthority> authorities;

    // ==========================================
    // CONSTRUCTOR
    // ==========================================

    private User(Builder builder) {
        this.id = builder.id;
        this.email = builder.email;
        this.firstName = builder.firstName;
        this.lastName = builder.lastName;
        this.username = builder.username;
        this.identityNo = builder.identityNo;
        this.phoneNumber = builder.phoneNumber;
        this.password = builder.password;
        this.roleNames = builder.roleNames != null ? builder.roleNames : new ArrayList<>();
        this.additionalPermissions = builder.additionalPermissions != null ? builder.additionalPermissions : new ArrayList<>();
        this.requestedRoles = builder.requestedRoles;
        this.department = builder.department;
        this.attributes = builder.attributes != null ? builder.attributes : new HashMap<>();
        this.status = builder.status;
        this.enabled = builder.enabled;
        this.accountLocked = builder.accountLocked;
        this.accountDisabled = builder.accountDisabled;
        this.emailVerified = builder.emailVerified;
        this.forcePasswordChange = builder.forcePasswordChange;
        this.phoneVerified = builder.phoneVerified;
        this.securityMetadata = builder.securityMetadata;
        this.passwordHistoryEntries = builder.passwordHistoryEntries != null ? builder.passwordHistoryEntries : new ArrayList<>();
        this.mfaEnabled = builder.mfaEnabled;
        this.mfaRequired = builder.mfaRequired;
        this.otpSecret = builder.otpSecret;
        this.loginAttempts = builder.loginAttempts;
        this.failedLoginAttempts = builder.failedLoginAttempts;
        this.lastLogin = builder.lastLogin;
        this.lastLoginIp = builder.lastLoginIp;
        this.lastLoginUserAgent = builder.lastLoginUserAgent;
        this.knownDeviceFingerprints = builder.knownDeviceFingerprints != null ? builder.knownDeviceFingerprints : "";
        this.passwordLastChanged = builder.passwordLastChanged;
        this.passwordExpiresAt = builder.passwordExpiresAt;
        this.passwordResetTokenHash = builder.passwordResetTokenHash;
        this.passwordResetTokenExpiresAt = builder.passwordResetTokenExpiresAt;
        this.verificationTokenHash = builder.verificationTokenHash;
        this.verificationTokenExpiresAt = builder.verificationTokenExpiresAt;
        this.approvalLevel = builder.approvalLevel;
        this.approvedAt = builder.approvedAt;
        this.approvedBy = builder.approvedBy;
        this.rejectedAt = builder.rejectedAt;
        this.rejectedBy = builder.rejectedBy;
        this.rejectionReason = builder.rejectionReason;
        this.profilePictureUrl = builder.profilePictureUrl;
        this.bio = builder.bio;
        this.userProfileId = builder.userProfileId;
        this.createdAt = builder.createdAt;
        this.createdBy = builder.createdBy;
        this.updatedAt = builder.updatedAt;
        this.authorities = builder.authorities;
    }

    // ==========================================
    // BUILDER CLASS
    // ==========================================

    public static class Builder {
        private String id;
        private String email;
        private String firstName;
        private String lastName;
        private String username;
        private String identityNo;
        private String phoneNumber;
        private String password;
        private List<String> roleNames;
        private List<String> additionalPermissions;
        private Set<Roles> requestedRoles;
        private String department;
        private Map<String, Object> attributes;
        private UserStatus status = UserStatus.PENDING_APPROVAL;
        private boolean enabled = false;
        private boolean accountLocked = false;
        private boolean accountDisabled = false;
        private boolean emailVerified = false;
        private boolean forcePasswordChange = false;
        private boolean phoneVerified = false;
        private SecurityMetadata securityMetadata;
        private List<UserPasswordHistory> passwordHistoryEntries;
        private boolean mfaEnabled = false;
        private boolean mfaRequired = false;
        private String otpSecret;
        private int loginAttempts = 0;
        private int failedLoginAttempts = 0;
        private Instant lastLogin;
        private String lastLoginIp;
        private String lastLoginUserAgent;
        private String knownDeviceFingerprints = "";
        private Instant passwordLastChanged;
        private Instant passwordExpiresAt;
        private String passwordResetTokenHash;
        private Instant passwordResetTokenExpiresAt;
        private String verificationTokenHash;
        private Instant verificationTokenExpiresAt;
        private ApprovalLevel approvalLevel;
        private Instant approvedAt;
        private String approvedBy;
        private Instant rejectedAt;
        private String rejectedBy;
        private String rejectionReason;
        private String profilePictureUrl;
        private String bio;
        private String userProfileId;
        private Instant createdAt;
        private String createdBy;
        private Instant updatedAt;
        private Collection<? extends GrantedAuthority> authorities;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        public Builder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder identityNo(String identityNo) {
            this.identityNo = identityNo;
            return this;
        }

        public Builder phoneNumber(String phoneNumber) {
            this.phoneNumber = phoneNumber;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder roleNames(List<String> roleNames) {
            this.roleNames = roleNames;
            return this;
        }

        public Builder additionalPermissions(List<String> additionalPermissions) {
            this.additionalPermissions = additionalPermissions;
            return this;
        }

        public Builder requestedRoles(Set<Roles> requestedRoles) {
            this.requestedRoles = requestedRoles;
            return this;
        }

        public Builder department(String department) {
            this.department = department;
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            this.attributes = attributes;
            return this;
        }

        public Builder status(UserStatus status) {
            this.status = status;
            return this;
        }

        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Builder accountLocked(boolean accountLocked) {
            this.accountLocked = accountLocked;
            return this;
        }

        public Builder accountDisabled(boolean accountDisabled) {
            this.accountDisabled = accountDisabled;
            return this;
        }

        public Builder emailVerified(boolean emailVerified) {
            this.emailVerified = emailVerified;
            return this;
        }

        public Builder forcePasswordChange(boolean forcePasswordChange) {
            this.forcePasswordChange = forcePasswordChange;
            return this;
        }

        public Builder phoneVerified(boolean phoneVerified) {
            this.phoneVerified = phoneVerified;
            return this;
        }

        public Builder securityMetadata(SecurityMetadata securityMetadata) {
            this.securityMetadata = securityMetadata;
            return this;
        }

        public Builder passwordHistoryEntries(List<UserPasswordHistory> passwordHistoryEntries) {
            this.passwordHistoryEntries = passwordHistoryEntries;
            return this;
        }

        public Builder mfaEnabled(boolean mfaEnabled) {
            this.mfaEnabled = mfaEnabled;
            return this;
        }

        public Builder mfaRequired(boolean mfaRequired) {
            this.mfaRequired = mfaRequired;
            return this;
        }

        public Builder otpSecret(String otpSecret) {
            this.otpSecret = otpSecret;
            return this;
        }

        public Builder loginAttempts(int loginAttempts) {
            this.loginAttempts = loginAttempts;
            return this;
        }

        public Builder failedLoginAttempts(int failedLoginAttempts) {
            this.failedLoginAttempts = failedLoginAttempts;
            return this;
        }

        public Builder lastLogin(Instant lastLogin) {
            this.lastLogin = lastLogin;
            return this;
        }

        public Builder lastLoginIp(String lastLoginIp) {
            this.lastLoginIp = lastLoginIp;
            return this;
        }

        public Builder lastLoginUserAgent(String lastLoginUserAgent) {
            this.lastLoginUserAgent = lastLoginUserAgent;
            return this;
        }

        public Builder knownDeviceFingerprints(String knownDeviceFingerprints) {
            this.knownDeviceFingerprints = knownDeviceFingerprints;
            return this;
        }

        public Builder passwordLastChanged(Instant passwordLastChanged) {
            this.passwordLastChanged = passwordLastChanged;
            return this;
        }

        public Builder passwordExpiresAt(Instant passwordExpiresAt) {
            this.passwordExpiresAt = passwordExpiresAt;
            return this;
        }

        public Builder passwordResetTokenHash(String passwordResetTokenHash) {
            this.passwordResetTokenHash = passwordResetTokenHash;
            return this;
        }

        public Builder passwordResetTokenExpiresAt(Instant passwordResetTokenExpiresAt) {
            this.passwordResetTokenExpiresAt = passwordResetTokenExpiresAt;
            return this;
        }

        public Builder verificationTokenHash(String verificationTokenHash) {
            this.verificationTokenHash = verificationTokenHash;
            return this;
        }

        public Builder verificationTokenExpiresAt(Instant verificationTokenExpiresAt) {
            this.verificationTokenExpiresAt = verificationTokenExpiresAt;
            return this;
        }

        public Builder approvalLevel(ApprovalLevel approvalLevel) {
            this.approvalLevel = approvalLevel;
            return this;
        }

        public Builder approvedAt(Instant approvedAt) {
            this.approvedAt = approvedAt;
            return this;
        }

        public Builder approvedBy(String approvedBy) {
            this.approvedBy = approvedBy;
            return this;
        }

        public Builder rejectedAt(Instant rejectedAt) {
            this.rejectedAt = rejectedAt;
            return this;
        }

        public Builder rejectedBy(String rejectedBy) {
            this.rejectedBy = rejectedBy;
            return this;
        }

        public Builder rejectionReason(String rejectionReason) {
            this.rejectionReason = rejectionReason;
            return this;
        }

        public Builder profilePictureUrl(String profilePictureUrl) {
            this.profilePictureUrl = profilePictureUrl;
            return this;
        }

        public Builder bio(String bio) {
            this.bio = bio;
            return this;
        }

        public Builder userProfileId(String userProfileId) {
            this.userProfileId = userProfileId;
            return this;
        }

        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public Builder createdBy(String createdBy) {
            this.createdBy = createdBy;
            return this;
        }

        public Builder updatedAt(Instant updatedAt) {
            this.updatedAt = updatedAt;
            return this;
        }

        public Builder authorities(Collection<? extends GrantedAuthority> authorities) {
            this.authorities = authorities;
            return this;
        }

        public User build() {
            return new User(this);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    // ==========================================
    // SPRING SECURITY UserDetails IMPLEMENTATION
    // ==========================================

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.authorities != null) {
            return this.authorities;
        }

        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        if (roleNames != null) {
            roleNames.forEach(role ->
                    grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role))
            );
        }

        if (additionalPermissions != null) {
            additionalPermissions.forEach(permission ->
                    grantedAuthorities.add(new SimpleGrantedAuthority(permission))
            );
        }

        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        // Account is non-expired if status is not DEACTIVATED
        return status != UserStatus.DEACTIVATED;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !isPasswordExpired();
    }

    @Override
    public boolean isEnabled() {
        return this.enabled && !this.accountDisabled;
    }

    // ==========================================
    // ROLE MANAGEMENT METHODS
    // ==========================================

    public Set<Roles> getRequestedRoles() {
        return requestedRoles == null || requestedRoles.isEmpty()
                ? Set.of(Roles.USER)
                : requestedRoles;
    }

    public Set<Roles> getRoles() {
        if (roleNames == null || roleNames.isEmpty()) {
            return Set.of(Roles.USER);
        }
        return roleNames.stream()
                .map(Roles::valueOf)
                .collect(Collectors.toSet());
    }

    public void addRole(Roles role) {
        if (this.roleNames == null) {
            this.roleNames = new ArrayList<>();
        }
        if (!this.roleNames.contains(role.name())) {
            this.roleNames.add(role.name());
        }
    }

    public void removeRole(Roles role) {
        if (this.roleNames != null) {
            this.roleNames.remove(role.name());
        }
    }

    public boolean hasRole(Roles role) {
        return this.roleNames != null && this.roleNames.contains(role.name());
    }

    public boolean hasAnyRole(Roles... roles) {
        if (this.roleNames == null) return false;
        return Arrays.stream(roles)
                .anyMatch(role -> this.roleNames.contains(role.name()));
    }

    public boolean hasHigherPrivilegesThan(Roles otherRole) {
        return getRoles().stream()
                .anyMatch(role -> role.getLevel() > otherRole.getLevel());
    }

    public Roles getHighestPriorityRole() {
        return getRoles().stream()
                .max(Comparator.comparingInt(Roles::getLevel))
                .orElse(Roles.USER);
    }

    // ==========================================
    // PERMISSION METHODS
    // ==========================================

    public void addPermission(String permission) {
        if (this.additionalPermissions == null) {
            this.additionalPermissions = new ArrayList<>();
        }
        if (!this.additionalPermissions.contains(permission)) {
            this.additionalPermissions.add(permission);
        }
    }

    /**
     * Returns all Permissions for this user, combining role-based defaults and additional permissions.
     */
    public Set<Permissions> getAllPermissions() {
        Set<Permissions> permissions = new HashSet<>();

        // 1️⃣ Map additionalPermissions (Strings) -> Permissions enum
        if (additionalPermissions != null) {
            additionalPermissions.stream()
                    .map(Permissions::fromNameSafe)
                    .flatMap(Optional::stream)
                    .forEach(permissions::add);
        }

        // 2️⃣ Map roleNames (Strings) -> default role Permissions
        if (roleNames != null) {
            roleNames.stream()
                    .map(Roles::fromName)
                    .flatMap(Optional::stream)
                    .flatMap(role -> Arrays.stream(getPermissionsForRole(role)))
                    .forEach(permissions::add);
        }

        return permissions;
    }

    /**
     * Helper to map Roles -> default Permissions.
     */
    private Permissions[] getPermissionsForRole(Roles role) {
        return switch (role) {
            case SUPER_ADMIN -> Permissions.getSuperAdminPermissions();
            case ADMIN       -> Permissions.getAdminPermissions();
            case MANAGER     -> Permissions.getManagerPermissions();
            case USER        -> Permissions.getUserPermissions();
        };
    }

    // ==========================================
    // ACCOUNT STATE CHECKS
    // ==========================================

    public boolean isActive() {
        return status == UserStatus.ACTIVE
                && enabled
                && !accountLocked
                && !accountDisabled;
    }

    public boolean isPendingApproval() {
        return status == UserStatus.PENDING_APPROVAL;
    }

    public boolean isPasswordExpired() {
        return passwordExpiresAt != null
                && Instant.now().isAfter(passwordExpiresAt);
    }

    public boolean needsPasswordChange() {
        return forcePasswordChange || isPasswordExpired();
    }

    // ==========================================
    // DEVICE FINGERPRINT METHODS
    // ==========================================

    public boolean isKnownDevice(String deviceFingerprint) {
        return knownDeviceFingerprints != null
                && knownDeviceFingerprints.contains(deviceFingerprint);
    }

    public void addKnownDevice(String deviceFingerprint) {
        this.knownDeviceFingerprints = deviceFingerprint;
    }

    // ==========================================
    // SECURITY METADATA HELPERS
    // ==========================================

    public SecurityMetadata getOrCreateSecurityMetadata() {
        if (this.securityMetadata == null) {
            this.securityMetadata = SecurityMetadata.builder()
                    .riskScore(0)
                    .riskLevel(SecurityMetadata.RiskLevel.LOW)
                    .build();
        }
        return this.securityMetadata;
    }

    // ==========================================
    // LOGIN TRACKING (Instant-based)
    // ==========================================

    /**
     * Record simple login
     */
    public void recordLogin(String ipAddress, String userAgent, Instant now) {
        this.lastLogin = now;
        this.lastLoginIp = ipAddress;
        this.lastLoginUserAgent = userAgent;
        this.loginAttempts++;
        this.failedLoginAttempts = 0;
    }

    /**
     * Record successful login with full tracking
     */
    public void recordSuccessfulLogin(
            String ipAddress,
            String userAgent,
            String deviceId,
            String country,
            String city,
            Instant now
    ) {
        this.lastLogin = now;
        this.lastLoginIp = ipAddress;
        this.lastLoginUserAgent = userAgent;
        this.loginAttempts++;
        this.failedLoginAttempts = 0;

        getOrCreateSecurityMetadata().login().recordSuccess(
                now, ipAddress, deviceId, country, city
        );
    }

    /**
     * Record failed login
     */
    public void recordFailedLogin(Instant now) {
        this.failedLoginAttempts++;
        getOrCreateSecurityMetadata().login().recordFailed(now);
    }

    /**
     * Check if temporarily locked
     */
    public boolean shouldBeTemporarilyLocked(Instant now, int threshold) {
        return getOrCreateSecurityMetadata().login().exceededThreshold(threshold) ||
                getOrCreateSecurityMetadata().locking().isTemporarilyLocked(now);
    }

    /**
     * Apply temporary lock
     */
    public void applyTemporaryLock(
            Instant now,
            Duration duration,
            String reason,
            SecurityMetadata.LockType type
    ) {
        getOrCreateSecurityMetadata().locking().apply(now, duration, reason, type);
    }

    // ==========================================
    // PASSWORD HISTORY (Instant-based)
    // ==========================================

    /**
     * Add password to history
     */
    public void addPasswordToHistory(
            String passwordHash,
            UserPasswordHistory.PasswordHashAlgorithm algorithm,
            UserPasswordHistory.PasswordChangeReason reason,
            String changedFromIp,
            Instant now
    ) {
        if (this.passwordHistoryEntries == null) {
            this.passwordHistoryEntries = new ArrayList<>();
        }

        passwordHistoryEntries.forEach(entry -> entry.setCurrent(false));

        UserPasswordHistory newEntry = UserPasswordHistory.builder()
                .passwordHash(passwordHash)
                .hashAlgorithm(algorithm)
                .changedAt(now)
                .changedFromIp(changedFromIp)
                .version(passwordHistoryEntries.size() + 1L)
                .reason(reason)
                .current(true)
                .build();

        passwordHistoryEntries.add(newEntry);

        while (passwordHistoryEntries.size() > 5) {
            passwordHistoryEntries.remove(0);
        }

        this.passwordLastChanged = now;
        getOrCreateSecurityMetadata().password().recordChange(now);
    }

    /**
     * Check if password recently used
     */
    public boolean isPasswordRecentlyUsed(String plainPassword, int checkLastN) {
        if (passwordHistoryEntries == null || passwordHistoryEntries.isEmpty()) {
            return false;
        }

        return passwordHistoryEntries.stream()
                .limit(checkLastN)
                .anyMatch(entry -> entry.matches(plainPassword));
    }

    // ==========================================
    // ACCOUNT OPERATIONS
    // ==========================================

    public void lockAccount() {
        this.accountLocked = true;
        this.status = UserStatus.LOCKED;
    }

    public void unlockAccount() {
        this.accountLocked = false;
        if (this.status == UserStatus.LOCKED) {
            this.status = UserStatus.ACTIVE;
        }
        this.failedLoginAttempts = 0;
    }

    public void approve(String approvedBy, Instant now) {
        this.status = UserStatus.ACTIVE;
        this.enabled = true;
        this.approvedAt = now;
        this.approvedBy = approvedBy;
        this.approvalLevel = ApprovalLevel.APPROVED;
    }

    public void reject(String rejectedBy, String reason, Instant now) {
        this.status = UserStatus.REJECTED;
        this.enabled = false;
        this.rejectedAt = now;
        this.rejectedBy = rejectedBy;
        this.rejectionReason = reason;
        this.approvalLevel = ApprovalLevel.REJECTED;
    }

    // ==========================================
    // UTILITY
    // ==========================================

    public String getFullName() {
        if (firstName == null && lastName == null) {
            return email;
        }
        return String.format("%s %s",
                firstName != null ? firstName : "",
                lastName != null ? lastName : ""
        ).trim();
    }

    @Override
    public String toString() {
        return String.format("User[id=%s, email=%s, roles=%s, status=%s]",
                id, email, roleNames, status);
    }
}