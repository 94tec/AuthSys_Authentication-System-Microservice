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

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * User Domain Model
 *
 * Represents a user in the AuthSys system with:
 * - Authentication credentials
 * - Authorization roles and permissions
 * - Security tracking (login attempts, device fingerprints)
 * - Profile information
 * - Approval workflow state
 *
 * Implements Spring Security's UserDetails for authentication integration
 * Stored in Firestore collection: "users"
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
    private String id;  // Firebase UID

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
    private String username;  // Optional, defaults to email

    // National ID or other identity number
    private String identityNo;

    // Phone number in E.164 format: +254712345678
    private String phoneNumber;

    // Password hash (stored in Firebase Auth, not Firestore)
    @JsonIgnore
    private transient String password;

    // ==========================================
    // ROLES & PERMISSIONS (RBAC/ABAC)
    // ==========================================

    /**
     * User's assigned roles (stored as strings for Firestore compatibility)
     * Examples: ["USER", "ADMIN", "MANAGER"]
     */
    @PropertyName("roles")
    @Builder.Default
    private List<String> roleNames = new ArrayList<>();

    /**
     * Additional permissions beyond role-based (for special cases)
     * Examples: ["read:sensitive_reports", "approve:large_expenses"]
     */
    @PropertyName("permissions")
    @Builder.Default
    private List<String> additionalPermissions = new ArrayList<>();

    /**
     * Role requested during registration (for approval workflow)
     */
    @PropertyName("requested_role")
    private Roles requestedRole;

    /**
     * User's department (for ABAC policies)
     * Examples: "Engineering", "Sales", "Finance"
     */
    private String department;

    /**
     * Custom attributes for ABAC evaluation
     * Examples: {"clearance_level": "SECRET", "region": "US-WEST"}
     */
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

    /**
     * Embedded security metadata
     */
    @PropertyName("security_metadata")
    private SecurityMetadata securityMetadata;

    /**
     * Password change history
     */
    @JsonIgnore
    @PropertyName("password_history")
    @Builder.Default
    private List<UserPasswordHistory> passwordHistoryEntries = new ArrayList<>();

    /**
     * MFA enabled flag (you have mfaRequired but not mfaEnabled)
     */
    @PropertyName("mfa_enabled")
    @Builder.Default
    private boolean mfaEnabled = false;
    /**
     * Password history for password reuse prevention
     * Stores hashes of last N passwords
     */
    @JsonIgnore
    @Builder.Default
    private List<String> passwordHistory = new ArrayList<>();

    /**
     * MFA/2FA Configuration
     */
    @PropertyName("mfa_required")
    @Builder.Default
    private boolean mfaRequired = false;

    @JsonIgnore
    @PropertyName("otp_secret")
    private String otpSecret;  // TOTP secret for MFA

    /**
     * Login Tracking
     */
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

    /**
     * Device fingerprints for known devices
     * Used for risk scoring and device verification
     */
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

    /**
     * Password reset token (hashed)
     */
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
    private String approvedBy;  // Admin user ID who approved

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
    private String userProfileId;  // Reference to separate UserProfile document

    // ==========================================
    // AUDIT FIELDS
    // ==========================================

    @PropertyName("created_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    @Builder.Default
    private Instant createdAt = Instant.now();

    @PropertyName("created_by")
    private String createdBy;  // System or admin who created the user

    @PropertyName("updated_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant updatedAt;

    // ==========================================
    // SPRING SECURITY INTEGRATION
    // ==========================================

    /**
     * Transient field - populated by UserDetailsService
     * Not stored in Firestore
     */
    @JsonIgnore
    private transient Collection<? extends GrantedAuthority> authorities;

    // ==========================================
    // ROLE MANAGEMENT METHODS
    // ==========================================

    /**
     * Get roles as enum Set (converted from string list)
     */
    public Set<Roles> getRoles() {
        if (roleNames == null || roleNames.isEmpty()) {
            return Set.of(Roles.USER);  // Default role
        }
        return roleNames.stream()
                .map(Roles::valueOf)
                .collect(Collectors.toSet());
    }

    /**
     * Add role (prevents duplicates)
     */
    public void addRole(Roles role) {
        if (this.roleNames == null) {
            this.roleNames = new ArrayList<>();
        }
        if (!this.roleNames.contains(role.name())) {
            this.roleNames.add(role.name());
        }
    }

    /**
     * Remove role
     */
    public void removeRole(Roles role) {
        if (this.roleNames != null) {
            this.roleNames.remove(role.name());
        }
    }

    /**
     * Check if user has specific role
     */
    public boolean hasRole(Roles role) {
        return this.roleNames != null && this.roleNames.contains(role.name());
    }

    /**
     * Check if user has any of the specified roles
     */
    public boolean hasAnyRole(Roles... roles) {
        if (this.roleNames == null) return false;
        return Arrays.stream(roles)
                .anyMatch(role -> this.roleNames.contains(role.name()));
    }

    /**
     * Check if user has higher privileges than another role
     */
    public boolean hasHigherPrivilegesThan(Roles otherRole) {
        return getRoles().stream()
                .anyMatch(role -> role.getPriority() > otherRole.getPriority());
    }

    /**
     * Get the highest priority role
     */
    public Roles getHighestPriorityRole() {
        return getRoles().stream()
                .max(Comparator.comparingInt(Roles::getPriority))
                .orElse(Roles.USER);
    }

    // ==========================================
    // PERMISSION METHODS
    // ==========================================

    /**
     * Add additional permission
     */
    public void addPermission(String permission) {
        if (this.additionalPermissions == null) {
            this.additionalPermissions = new ArrayList<>();
        }
        if (!this.additionalPermissions.contains(permission)) {
            this.additionalPermissions.add(permission);
        }
    }

    /**
     * Get all permissions (role-based + additional)
     * Note: This is a simplified view. Full permission resolution
     * should be done by PermissionService
     */
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

    /**
     * Check if account is active and can authenticate
     */
    public boolean isActive() {
        return status == UserStatus.ACTIVE
                && enabled
                && !accountLocked
                && !accountDisabled;
    }

    /**
     * Check if account is pending approval
     */
    public boolean isPendingApproval() {
        return status == UserStatus.PENDING_APPROVAL;
    }

    /**
     * Check if password has expired
     */
    public boolean isPasswordExpired() {
        return passwordExpiresAt != null
                && Instant.now().isAfter(passwordExpiresAt);
    }

    /**
     * Check if user needs to change password
     */
    public boolean needsPasswordChange() {
        return forcePasswordChange || isPasswordExpired();
    }

    // ==========================================
    // DEVICE FINGERPRINT METHODS
    // ==========================================

    /**
     * Check if device is known/trusted
     */
    public boolean isKnownDevice(String deviceFingerprint) {
        return knownDeviceFingerprints != null
                && knownDeviceFingerprints.contains(deviceFingerprint);
    }

    /**
     * Register new trusted device
     */
    public void addKnownDevice(String deviceFingerprint) {
        if (this.knownDeviceFingerprints == null) {
            this.knownDeviceFingerprints = new HashSet<>();
        }
        this.knownDeviceFingerprints.add(deviceFingerprint);
    }

    // ==========================================
    // SPRING SECURITY UserDetails IMPLEMENTATION
    // ==========================================

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.authorities != null) {
            return this.authorities;
        }

        // Build authorities from roles
        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        // Add role authorities
        if (roleNames != null) {
            roleNames.forEach(role ->
                    grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role))
            );
        }

        // Add permission authorities
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
        return this.email;  // Use email as username
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
    // UTILITY METHODS
    // ==========================================

    /**
     * Initialize security metadata if not present
     */
    public SecurityMetadata getOrCreateSecurityMetadata() {
        if (this.securityMetadata == null) {
            this.securityMetadata = SecurityMetadata.builder()
                    .riskScore(0)
                    .riskLevel(SecurityMetadata.RiskLevel.LOW)
                    .build();
        }
        return this.securityMetadata;
    }

    /**
     * Record login using security metadata
     */
    public void recordLogin(String ipAddress, String userAgent, String deviceId,
                            String country, String city, Clock clock) {
        this.lastLogin = clock.instant();
        this.lastLoginIp = ipAddress;
        this.lastLoginUserAgent = userAgent;
        this.loginAttempts++;

        // Update security metadata
        getOrCreateSecurityMetadata().recordSuccessfulLogin(
                clock, ipAddress, deviceId, country, city
        );
    }

    /**
     * Record failed login using security metadata
     */
    public void recordFailedLogin(Clock clock) {
        this.failedLoginAttempts++;
        getOrCreateSecurityMetadata().recordFailedLogin(clock);
    }

    /**
     * Check if account should be temporarily locked
     */
    public boolean shouldBeTemporarilyLocked(Clock clock, int threshold) {
        return getOrCreateSecurityMetadata().hasExceededFailedLoginThreshold(threshold) ||
                getOrCreateSecurityMetadata().isTemporarilyLocked(clock);
    }

    /**
     * Add password to history
     */
    public void addPasswordToHistory(
            String passwordHash,
            UserPasswordHistory.PasswordHashAlgorithm algorithm,
            UserPasswordHistory.PasswordChangeReason reason,
            String changedFromIp,
            Clock clock
    ) {
        if (this.passwordHistoryEntries == null) {
            this.passwordHistoryEntries = new ArrayList<>();
        }

        // Mark all previous entries as non-current
        passwordHistoryEntries.forEach(entry -> entry.setCurrent(false));

        // Create new history entry
        UserPasswordHistory newEntry = UserPasswordHistory.builder()
                .passwordHash(passwordHash)
                .hashAlgorithm(algorithm)
                .changedAt(clock.instant())
                .changedFromIp(changedFromIp)
                .version(passwordHistoryEntries.size() + 1L)
                .reason(reason)
                .current(true)
                .build();

        passwordHistoryEntries.add(newEntry);

        // Keep only last N passwords (e.g., 5)
        int maxHistory = 5;
        while (passwordHistoryEntries.size() > maxHistory) {
            passwordHistoryEntries.remove(0);
        }

        // Update password metadata
        this.passwordLastChanged = clock.instant();
        getOrCreateSecurityMetadata().recordPasswordChange(clock);
    }

    /**
     * Check if password was recently used
     */
    public boolean isPasswordRecentlyUsed(String plainPassword, int checkLastN) {
        if (passwordHistoryEntries == null || passwordHistoryEntries.isEmpty()) {
            return false;
        }

        return passwordHistoryEntries.stream()
                .limit(checkLastN)
                .anyMatch(entry -> entry.matches(plainPassword));
    }
    /**
     * Get user's full name
     */
    public String getFullName() {
        if (firstName == null && lastName == null) {
            return email;
        }
        return String.format("%s %s",
                firstName != null ? firstName : "",
                lastName != null ? lastName : ""
        ).trim();
    }

    /**
     * Update last login timestamp and IP
     */
    public void recordLogin(String ipAddress, String userAgent) {
        this.lastLogin = Instant.now();
        this.lastLoginIp = ipAddress;
        this.lastLoginUserAgent = userAgent;
        this.loginAttempts++;
        this.failedLoginAttempts = 0;  // Reset on successful login
    }

    /**
     * Increment failed login attempts
     */
    public void recordFailedLogin() {
        this.failedLoginAttempts++;
    }

    /**
     * Reset failed login attempts
     */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
    }

    /**
     * Lock account (e.g., after too many failed logins)
     */
    public void lockAccount() {
        this.accountLocked = true;
        this.status = UserStatus.LOCKED;
    }

    /**
     * Unlock account
     */
    public void unlockAccount() {
        this.accountLocked = false;
        if (this.status == UserStatus.LOCKED) {
            this.status = UserStatus.ACTIVE;
        }
        this.failedLoginAttempts = 0;
    }

    /**
     * Approve user account
     */
    public void approve(String approvedBy) {
        this.status = UserStatus.ACTIVE;
        this.enabled = true;
        this.approvedAt = Instant.now();
        this.approvedBy = approvedBy;
        this.approvalLevel = ApprovalLevel.APPROVED;
    }

    /**
     * Reject user account
     */
    public void reject(String rejectedBy, String reason) {
        this.status = UserStatus.REJECTED;
        this.enabled = false;
        this.rejectedAt = Instant.now();
        this.rejectedBy = rejectedBy;
        this.rejectionReason = reason;
        this.approvalLevel = ApprovalLevel.REJECTED;
    }

    @Override
    public String toString() {
        return String.format("User[id=%s, email=%s, roles=%s, status=%s]",
                id, email, roleNames, status);
    }
}