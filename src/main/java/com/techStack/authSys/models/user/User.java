package com.techStack.authSys.models.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.cloud.firestore.annotation.DocumentId;
import com.google.cloud.firestore.annotation.PropertyName;
import com.google.cloud.spring.data.firestore.Document;
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
@Builder
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
    @Builder.Default
    private List<String> roleNames = new ArrayList<>();

    @PropertyName("permissions")
    @Builder.Default
    private List<String> additionalPermissions = new ArrayList<>();

    @PropertyName("requested_role")
    private Roles requestedRole;

    private String department;

    @Builder.Default
    private Map<String, Object> attributes = new HashMap<>();

    // ==========================================
    // ACCOUNT STATUS & STATE
    // ==========================================

    @PropertyName("status")
    @Builder.Default
    private UserStatus status = UserStatus.PENDING_APPROVAL;

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

    @PropertyName("force_password_change")
    @Builder.Default
    private boolean forcePasswordChange = false;

    // ==========================================
    // SECURITY & AUTHENTICATION
    // ==========================================

    @PropertyName("security_metadata")
    private SecurityMetadata securityMetadata;

    @JsonIgnore
    @PropertyName("password_history")
    @Builder.Default
    private List<UserPasswordHistory> passwordHistoryEntries = new ArrayList<>();

    @PropertyName("mfa_enabled")
    @Builder.Default
    private boolean mfaEnabled = false;

    @PropertyName("mfa_required")
    @Builder.Default
    private boolean mfaRequired = false;

    @JsonIgnore
    @PropertyName("otp_secret")
    private String otpSecret;

    @PropertyName("login_attempts")
    @Builder.Default
    private int loginAttempts = 0;

    @PropertyName("failed_login_attempts")
    @Builder.Default
    private int failedLoginAttempts = 0;

    @PropertyName("last_login")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant lastLogin;

    @PropertyName("last_login_ip")
    private String lastLoginIp;

    @PropertyName("last_login_user_agent")
    private String lastLoginUserAgent;

    @PropertyName("known_device_fingerprints")
    @Builder.Default
    private Set<String> knownDeviceFingerprints = new HashSet<>();

    // ==========================================
    // PASSWORD MANAGEMENT
    // ==========================================

    @PropertyName("password_last_changed")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant passwordLastChanged;

    @PropertyName("password_expires_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant passwordExpiresAt;

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
    // ROLE MANAGEMENT METHODS
    // ==========================================

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

    public Set<String> getAllPermissions() {
        Set<String> permissions = new HashSet<>();
        if (additionalPermissions != null) {
            permissions.addAll(additionalPermissions);
        }
        return permissions;
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
        if (this.knownDeviceFingerprints == null) {
            this.knownDeviceFingerprints = new HashSet<>();
        }
        this.knownDeviceFingerprints.add(deviceFingerprint);
    }

    // ==========================================
    // SPRING SECURITY UserDetails
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