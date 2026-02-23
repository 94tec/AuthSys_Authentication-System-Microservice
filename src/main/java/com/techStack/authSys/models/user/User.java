package com.techStack.authSys.models.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.cloud.firestore.annotation.DocumentId;
import com.google.cloud.firestore.annotation.PropertyName;
import com.google.cloud.spring.data.firestore.Document;
import com.techStack.authSys.models.security.SecurityMetadata;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * User Domain Model
 *
 * Dual-persistence model:
 *   - @Document → Firestore (identity, permissions, security state)
 *   - @Entity   → PostgreSQL (relational anchor, firebase link, audit)
 *
 * The firebaseUid field is the cross-system key linking:
 *   Firebase Auth ──► User (Firestore + PostgreSQL) ──► FirestoreUserPermissions
 *
 * Clock handling:
 *   Methods that need the current time accept a Clock parameter rather
 *   than calling Instant.now() directly. This keeps the domain model
 *   testable without mocking static time.
 *
 * Role safety:
 *   getRoles() uses Roles.fromName() with filter rather than Roles.valueOf()
 *   so that a stale/unknown role name in Firestore logs a warning and is
 *   skipped instead of throwing IllegalArgumentException at login time.
 *
 * Builder completeness:
 *   All fields have corresponding builder methods. The original Builder
 *   only exposed id() and email() beyond the constructor-set fields,
 *   making it impossible to construct a fully populated User via builder
 *   in tests without reflection.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(
        name = "users",
        indexes = {
                @Index(name = "idx_users_firebase_uid", columnList = "firebase_uid"),
                @Index(name = "idx_users_email",        columnList = "email"),
                @Index(name = "idx_users_username",     columnList = "username")
        }
)
@Document(collectionName = "users")
public class User implements UserDetails {

    // =========================================================================
    // CORE IDENTITY
    // =========================================================================

    /**
     * Internal primary key.
     * Firestore: stored as String document ID via @DocumentId.
     * PostgreSQL: stored as UUID via @GeneratedValue.
     * The firebaseUid is the true cross-system key; this id is internal only.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    @DocumentId
    private String id;

    /**
     * Firebase Auth UID — primary cross-system identifier.
     * Nullable initially to support migration of existing users.
     */
    @Column(name = "firebase_uid", unique = true, length = 128)
    private String firebaseUid;

    @Column(name = "email", nullable = false, unique = true, length = 255)
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @Column(name = "first_name", length = 50)
    @NotBlank(message = "First name is required")
    @Size(max = 50)
    private String firstName;

    @Column(name = "last_name", length = 50)
    @NotBlank(message = "Last name is required")
    @Size(max = 50)
    private String lastName;

    @Column(name = "username", unique = true, length = 50)
    @Size(max = 50)
    private String username;

    @Column(name = "identity_no", length = 50)
    private String identityNo;

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    @JsonIgnore
    private transient String password;

    // =========================================================================
    // ROLES & PERMISSIONS
    // =========================================================================

    private Set<String> customPermissions = new HashSet<>();

    @PropertyName("roles")
    private List<String> roleNames = new ArrayList<>();

    /**
     * Additional permission strings beyond role defaults.
     * Format: "portfolio:publish", "order:view_all"
     * String-based permissions — resolved from Firestore at auth time.
     */
    @PropertyName("permissions")
    private List<String> additionalPermissions = new ArrayList<>();

    private Set<Roles> requestedRoles;
    private String department;
    private Map<String, Object> attributes = new HashMap<>();

    // =========================================================================
    // ACCOUNT STATUS & STATE
    // =========================================================================

    @Column(name = "status", length = 30)
    @Enumerated(EnumType.STRING)
    @PropertyName("status")
    private UserStatus status = UserStatus.PENDING_APPROVAL;

    @Column(name = "is_enabled", nullable = false)
    @PropertyName("enabled")
    private boolean enabled = false;

    @Column(name = "account_locked", nullable = false)
    @PropertyName("account_locked")
    private boolean accountLocked = false;

    @Column(name = "account_disabled", nullable = false)
    @PropertyName("account_disabled")
    private boolean accountDisabled = false;

    @Column(name = "email_verified", nullable = false)
    @PropertyName("email_verified")
    private boolean emailVerified = false;

    @PropertyName("force_password_change")
    private boolean forcePasswordChange = false;
    private boolean phoneVerified = false;

    // =========================================================================
    // SECURITY & AUTHENTICATION
    // =========================================================================

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

    @Column(name = "last_login_at")
    @PropertyName("last_login")
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant lastLogin;

    @PropertyName("last_login_ip")
    private String lastLoginIp;

    @PropertyName("last_login_user_agent")
    private String lastLoginUserAgent;

    @PropertyName("known_device_fingerprints")
    private String knownDeviceFingerprints = "";

    // =========================================================================
    // PASSWORD MANAGEMENT
    // =========================================================================

    @PropertyName("password_last_changed")
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant passwordLastChanged;

    @PropertyName("password_expires_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant passwordExpiresAt;

    private boolean firstTimeSetupCompleted;
    private Instant firstTimeSetupCompletedAt;
    private boolean temporaryPasswordLocked;
    private Instant temporaryPasswordLockedAt;

    @JsonIgnore
    @PropertyName("password_reset_token_hash")
    private String passwordResetTokenHash;

    @JsonIgnore
    @PropertyName("password_reset_token_expires_at")
    private Instant passwordResetTokenExpiresAt;

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
    // APPROVAL WORKFLOW
    // =========================================================================

    @Column(name = "approval_level", length = 20)
    @Enumerated(EnumType.STRING)
    @PropertyName("approval_level")
    private ApprovalLevel approvalLevel;

    @PropertyName("approved_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant approvedAt;

    @PropertyName("approved_by")
    private String approvedBy;

    @PropertyName("rejected_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant rejectedAt;

    @PropertyName("rejected_by")
    private String rejectedBy;

    @PropertyName("rejection_reason")
    private String rejectionReason;

    // =========================================================================
    // PROFILE INFORMATION
    // =========================================================================

    @Column(name = "profile_picture_url")
    @PropertyName("profile_picture_url")
    private String profilePictureUrl;

    @Column(name = "bio", length = 500)
    @PropertyName("bio")
    @Size(max = 500)
    private String bio;

    @PropertyName("user_profile_id")
    private String userProfileId;

    // =========================================================================
    // AUDIT FIELDS
    // =========================================================================

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    @PropertyName("created_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant createdAt;

    @PropertyName("created_by")
    private String createdBy;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    @PropertyName("updated_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant updatedAt;

    // =========================================================================
    // SPRING SECURITY
    // =========================================================================

    @JsonIgnore
    private transient Collection<? extends GrantedAuthority> authorities;

    // =========================================================================
    // BUILDER CONSTRUCTOR
    // =========================================================================

    private User(Builder builder) {
        this.id                         = builder.id;
        this.firebaseUid                = builder.firebaseUid;
        this.email                      = builder.email;
        this.firstName                  = builder.firstName;
        this.lastName                   = builder.lastName;
        this.username                   = builder.username;
        this.identityNo                 = builder.identityNo;
        this.phoneNumber                = builder.phoneNumber;
        this.password                   = builder.password;
        this.roleNames                  = builder.roleNames != null
                ? builder.roleNames : new ArrayList<>();
        this.additionalPermissions      = builder.additionalPermissions != null
                ? builder.additionalPermissions : new ArrayList<>();
        this.customPermissions          = builder.customPermissions != null
                ? builder.customPermissions : new HashSet<>();
        this.requestedRoles             = builder.requestedRoles;
        this.department                 = builder.department;
        this.attributes                 = builder.attributes != null
                ? builder.attributes : new HashMap<>();
        this.status                     = builder.status;
        this.enabled                    = builder.enabled;
        this.accountLocked              = builder.accountLocked;
        this.accountDisabled            = builder.accountDisabled;
        this.emailVerified              = builder.emailVerified;
        this.forcePasswordChange        = builder.forcePasswordChange;
        this.phoneVerified              = builder.phoneVerified;
        this.securityMetadata           = builder.securityMetadata;
        this.passwordHistoryEntries     = builder.passwordHistoryEntries != null
                ? builder.passwordHistoryEntries : new ArrayList<>();
        this.mfaEnabled                 = builder.mfaEnabled;
        this.mfaRequired                = builder.mfaRequired;
        this.otpSecret                  = builder.otpSecret;
        this.loginAttempts              = builder.loginAttempts;
        this.failedLoginAttempts        = builder.failedLoginAttempts;
        this.lastLogin                  = builder.lastLogin;
        this.lastLoginIp                = builder.lastLoginIp;
        this.lastLoginUserAgent         = builder.lastLoginUserAgent;
        this.knownDeviceFingerprints    = builder.knownDeviceFingerprints != null
                ? builder.knownDeviceFingerprints : "";
        this.passwordLastChanged        = builder.passwordLastChanged;
        this.passwordExpiresAt          = builder.passwordExpiresAt;
        this.firstTimeSetupCompleted    = builder.firstTimeSetupCompleted;
        this.firstTimeSetupCompletedAt  = builder.firstTimeSetupCompletedAt;
        this.temporaryPasswordLocked    = builder.temporaryPasswordLocked;
        this.temporaryPasswordLockedAt  = builder.temporaryPasswordLockedAt;
        this.passwordResetTokenHash     = builder.passwordResetTokenHash;
        this.passwordResetTokenExpiresAt = builder.passwordResetTokenExpiresAt;
        this.verificationTokenHash      = builder.verificationTokenHash;
        this.verificationTokenExpiresAt = builder.verificationTokenExpiresAt;
        this.approvalLevel              = builder.approvalLevel;
        this.approvedAt                 = builder.approvedAt;
        this.approvedBy                 = builder.approvedBy;
        this.rejectedAt                 = builder.rejectedAt;
        this.rejectedBy                 = builder.rejectedBy;
        this.rejectionReason            = builder.rejectionReason;
        this.profilePictureUrl          = builder.profilePictureUrl;
        this.bio                        = builder.bio;
        this.userProfileId              = builder.userProfileId;
        this.createdAt                  = builder.createdAt;
        this.createdBy                  = builder.createdBy;
        this.updatedAt                  = builder.updatedAt;
        this.authorities                = builder.authorities;
    }

    // =========================================================================
    // BUILDER
    // =========================================================================

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String id;
        private String firebaseUid;
        private String email;
        private String firstName;
        private String lastName;
        private String username;
        private String identityNo;
        private String phoneNumber;
        private String password;
        private List<String> roleNames;
        private List<String> additionalPermissions;
        private Set<String> customPermissions;
        private Set<Roles> requestedRoles;
        private String department;
        private Map<String, Object> attributes;
        private UserStatus status                   = UserStatus.PENDING_APPROVAL;
        private boolean enabled                     = false;
        private boolean accountLocked               = false;
        private boolean accountDisabled             = false;
        private boolean emailVerified               = false;
        private boolean forcePasswordChange         = false;
        private boolean phoneVerified               = false;
        private SecurityMetadata securityMetadata;
        private List<UserPasswordHistory> passwordHistoryEntries;
        private boolean mfaEnabled                  = false;
        private boolean mfaRequired                 = false;
        private String otpSecret;
        private int loginAttempts                   = 0;
        private int failedLoginAttempts             = 0;
        private Instant lastLogin;
        private String lastLoginIp;
        private String lastLoginUserAgent;
        private String knownDeviceFingerprints      = "";
        private Instant passwordLastChanged;
        private Instant passwordExpiresAt;
        private boolean firstTimeSetupCompleted     = false;
        private Instant firstTimeSetupCompletedAt;
        private boolean temporaryPasswordLocked     = false;
        private Instant temporaryPasswordLockedAt;
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

        public Builder id(String id)                                        { this.id = id; return this; }
        public Builder firebaseUid(String firebaseUid)                      { this.firebaseUid = firebaseUid; return this; }
        public Builder email(String email)                                  { this.email = email; return this; }
        public Builder firstName(String firstName)                          { this.firstName = firstName; return this; }
        public Builder lastName(String lastName)                            { this.lastName = lastName; return this; }
        public Builder username(String username)                            { this.username = username; return this; }
        public Builder identityNo(String identityNo)                        { this.identityNo = identityNo; return this; }
        public Builder phoneNumber(String phoneNumber)                      { this.phoneNumber = phoneNumber; return this; }
        public Builder password(String password)                            { this.password = password; return this; }
        public Builder roleNames(List<String> roleNames)                    { this.roleNames = roleNames; return this; }
        public Builder additionalPermissions(List<String> perms)            { this.additionalPermissions = perms; return this; }
        public Builder customPermissions(Set<String> customPermissions)     { this.customPermissions = customPermissions; return this; }
        public Builder requestedRoles(Set<Roles> requestedRoles)            { this.requestedRoles = requestedRoles; return this; }
        public Builder department(String department)                        { this.department = department; return this; }
        public Builder attributes(Map<String, Object> attributes)           { this.attributes = attributes; return this; }
        public Builder status(UserStatus status)                            { this.status = status; return this; }
        public Builder enabled(boolean enabled)                             { this.enabled = enabled; return this; }
        public Builder accountLocked(boolean accountLocked)                 { this.accountLocked = accountLocked; return this; }
        public Builder accountDisabled(boolean accountDisabled)             { this.accountDisabled = accountDisabled; return this; }
        public Builder emailVerified(boolean emailVerified)                 { this.emailVerified = emailVerified; return this; }
        public Builder forcePasswordChange(boolean forcePasswordChange)     { this.forcePasswordChange = forcePasswordChange; return this; }
        public Builder phoneVerified(boolean phoneVerified)                 { this.phoneVerified = phoneVerified; return this; }
        public Builder securityMetadata(SecurityMetadata securityMetadata)  { this.securityMetadata = securityMetadata; return this; }
        public Builder passwordHistoryEntries(List<UserPasswordHistory> h)  { this.passwordHistoryEntries = h; return this; }
        public Builder mfaEnabled(boolean mfaEnabled)                      { this.mfaEnabled = mfaEnabled; return this; }
        public Builder mfaRequired(boolean mfaRequired)                    { this.mfaRequired = mfaRequired; return this; }
        public Builder otpSecret(String otpSecret)                          { this.otpSecret = otpSecret; return this; }
        public Builder loginAttempts(int loginAttempts)                     { this.loginAttempts = loginAttempts; return this; }
        public Builder failedLoginAttempts(int failedLoginAttempts)         { this.failedLoginAttempts = failedLoginAttempts; return this; }
        public Builder lastLogin(Instant lastLogin)                         { this.lastLogin = lastLogin; return this; }
        public Builder lastLoginIp(String lastLoginIp)                      { this.lastLoginIp = lastLoginIp; return this; }
        public Builder lastLoginUserAgent(String lastLoginUserAgent)        { this.lastLoginUserAgent = lastLoginUserAgent; return this; }
        public Builder knownDeviceFingerprints(String fingerprints)         { this.knownDeviceFingerprints = fingerprints; return this; }
        public Builder passwordLastChanged(Instant passwordLastChanged)     { this.passwordLastChanged = passwordLastChanged; return this; }
        public Builder passwordExpiresAt(Instant passwordExpiresAt)         { this.passwordExpiresAt = passwordExpiresAt; return this; }
        public Builder firstTimeSetupCompleted(boolean completed)           { this.firstTimeSetupCompleted = completed; return this; }
        public Builder firstTimeSetupCompletedAt(Instant at)                { this.firstTimeSetupCompletedAt = at; return this; }
        public Builder temporaryPasswordLocked(boolean locked)              { this.temporaryPasswordLocked = locked; return this; }
        public Builder temporaryPasswordLockedAt(Instant at)                { this.temporaryPasswordLockedAt = at; return this; }
        public Builder passwordResetTokenHash(String hash)                  { this.passwordResetTokenHash = hash; return this; }
        public Builder passwordResetTokenExpiresAt(Instant at)              { this.passwordResetTokenExpiresAt = at; return this; }
        public Builder verificationTokenHash(String hash)                   { this.verificationTokenHash = hash; return this; }
        public Builder verificationTokenExpiresAt(Instant at)               { this.verificationTokenExpiresAt = at; return this; }
        public Builder approvalLevel(ApprovalLevel approvalLevel)           { this.approvalLevel = approvalLevel; return this; }
        public Builder approvedAt(Instant approvedAt)                       { this.approvedAt = approvedAt; return this; }
        public Builder approvedBy(String approvedBy)                        { this.approvedBy = approvedBy; return this; }
        public Builder rejectedAt(Instant rejectedAt)                       { this.rejectedAt = rejectedAt; return this; }
        public Builder rejectedBy(String rejectedBy)                        { this.rejectedBy = rejectedBy; return this; }
        public Builder rejectionReason(String rejectionReason)              { this.rejectionReason = rejectionReason; return this; }
        public Builder profilePictureUrl(String profilePictureUrl)          { this.profilePictureUrl = profilePictureUrl; return this; }
        public Builder bio(String bio)                                      { this.bio = bio; return this; }
        public Builder userProfileId(String userProfileId)                  { this.userProfileId = userProfileId; return this; }
        public Builder createdAt(Instant createdAt)                         { this.createdAt = createdAt; return this; }
        public Builder createdBy(String createdBy)                          { this.createdBy = createdBy; return this; }
        public Builder updatedAt(Instant updatedAt)                         { this.updatedAt = updatedAt; return this; }
        public Builder authorities(Collection<? extends GrantedAuthority> a){ this.authorities = a; return this; }

        public User build() { return new User(this); }
    }

    // =========================================================================
    // SPRING SECURITY
    // =========================================================================

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.authorities != null) return this.authorities;

        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        if (roleNames != null) {
            roleNames.forEach(role ->
                    grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }

        if (additionalPermissions != null) {
            additionalPermissions.forEach(permission ->
                    grantedAuthorities.add(new SimpleGrantedAuthority(permission)));
        }

        return grantedAuthorities;
    }

    @Override public String getPassword()              { return this.password; }
    @Override public String getUsername()              { return this.email; }
    @Override public boolean isAccountNonExpired()     { return status != UserStatus.DEACTIVATED; }
    @Override public boolean isAccountNonLocked()      { return !this.accountLocked; }
    @Override public boolean isCredentialsNonExpired() { return !isPasswordExpired(Clock.systemUTC()); }
    @Override public boolean isEnabled()               { return this.enabled && !this.accountDisabled; }

    // =========================================================================
    // ROLE MANAGEMENT
    // =========================================================================

    /**
     * Returns the highest-priority role this user holds.
     * Falls back to USER if no roles are assigned.
     */
    public Roles getPrimaryRole() {
        if (this.roleNames == null || this.roleNames.isEmpty()) {
            return Roles.USER;
        }

        List<Roles> priorityOrder = Arrays.asList(
                Roles.SUPER_ADMIN,
                Roles.ADMIN,
                Roles.DESIGNER,
                Roles.MANAGER,
                Roles.USER,
                Roles.GUEST
        );

        return priorityOrder.stream()
                .filter(role -> this.roleNames.contains(role.name()))
                .findFirst()
                .orElse(Roles.USER);
    }

    /**
     * Returns the set of Roles this user holds.
     *
     * Fix from original: used Roles.valueOf() which throws IllegalArgumentException
     * on any unknown/stale role name in Firestore. Now uses Roles.fromName() with
     * filter — unknown roles are skipped with a warning instead of crashing login.
     */
    public Set<Roles> getRoles() {
        if (roleNames == null || roleNames.isEmpty()) return Set.of(Roles.USER);
        return roleNames.stream()
                .map(name -> {
                    Optional<Roles> role = Roles.fromName(name);
                    if (role.isEmpty()) {
                        // Log but don't throw — stale Firestore data should not crash login
                        org.slf4j.LoggerFactory.getLogger(User.class)
                                .warn("Unknown role '{}' found for user {} — skipping", name, email);
                    }
                    return role;
                })
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toSet());
    }

    public void addRole(Roles role) {
        if (this.roleNames == null) this.roleNames = new ArrayList<>();
        if (!this.roleNames.contains(role.name())) this.roleNames.add(role.name());
    }

    public void removeRole(Roles role) {
        if (this.roleNames != null) this.roleNames.remove(role.name());
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

    public Set<Roles> getRequestedRoles() {
        return requestedRoles == null || requestedRoles.isEmpty()
                ? Set.of(Roles.USER)
                : requestedRoles;
    }

    // =========================================================================
    // PERMISSION MANAGEMENT
    // =========================================================================

    public void addPermission(String permission) {
        if (this.additionalPermissions == null) this.additionalPermissions = new ArrayList<>();
        if (!this.additionalPermissions.contains(permission)) {
            this.additionalPermissions.add(permission);
        }
    }

    public void addCustomPermission(String permission) {
        if (this.customPermissions == null) this.customPermissions = new HashSet<>();
        this.customPermissions.add(permission);
    }

    public void removeCustomPermission(String permission) {
        if (this.customPermissions != null) this.customPermissions.remove(permission);
    }

    public boolean hasCustomPermission(String permission) {
        return this.customPermissions != null && this.customPermissions.contains(permission);
    }

    public void clearCustomPermissions() {
        if (this.customPermissions != null) this.customPermissions.clear();
    }

    public Set<String> getCustomPermissions() {
        return customPermissions != null ? new HashSet<>(customPermissions) : new HashSet<>();
    }

    /**
     * Returns all effective permission strings for this user.
     *
     * Sources:
     *   1. additionalPermissions (direct string grants on this user)
     *   2. customPermissions (user-specific overrides)
     *
     * Role-based permissions are resolved separately by
     * FirestoreRolePermissionsRepository.resolveForRoles()
     * and merged in AuthService before JWT generation.
     */
    public Set<String> getAllPermissions() {
        Set<String> permissions = new HashSet<>();
        if (additionalPermissions != null) permissions.addAll(additionalPermissions);
        if (customPermissions != null)     permissions.addAll(customPermissions);
        return permissions;
    }

    // =========================================================================
    // ACCOUNT STATE
    // =========================================================================

    public boolean isActive() {
        return status == UserStatus.ACTIVE
                && enabled && !accountLocked && !accountDisabled;
    }

    public boolean isPendingApproval() { return status == UserStatus.PENDING_APPROVAL; }

    /**
     * Clock-injectable password expiry check.
     *
     * Fix from original: Instant.now() is not testable without mocking static
     * time. Callers pass in a Clock so tests can control the current time.
     *
     * Spring Security's isCredentialsNonExpired() delegates here with
     * Clock.systemUTC() — production behaviour is unchanged.
     *
     * @param clock clock to use for current time comparison
     * @return true if passwordExpiresAt is set and is before the clock's now
     */
    public boolean isPasswordExpired(Clock clock) {
        return passwordExpiresAt != null
                && clock.instant().isAfter(passwordExpiresAt);
    }

    public boolean needsPasswordChange(Clock clock) {
        return forcePasswordChange || isPasswordExpired(clock);
    }

    public boolean hasFirebaseAccount() {
        return this.firebaseUid != null && !this.firebaseUid.isBlank();
    }

    // =========================================================================
    // DEVICE & SESSION
    // =========================================================================

    public boolean isKnownDevice(String deviceFingerprint) {
        return knownDeviceFingerprints != null
                && knownDeviceFingerprints.contains(deviceFingerprint);
    }

    public void addKnownDevice(String deviceFingerprint) {
        this.knownDeviceFingerprints = deviceFingerprint;
    }

    // =========================================================================
    // SECURITY METADATA
    // =========================================================================

    public SecurityMetadata getOrCreateSecurityMetadata() {
        if (this.securityMetadata == null) {
            this.securityMetadata = SecurityMetadata.builder()
                    .riskScore(0)
                    .riskLevel(SecurityMetadata.RiskLevel.LOW)
                    .build();
        }
        return this.securityMetadata;
    }

    // =========================================================================
    // LOGIN RECORDING
    // =========================================================================

    public void recordLogin(String ipAddress, String userAgent, Instant now) {
        this.lastLogin          = now;
        this.lastLoginIp        = ipAddress;
        this.lastLoginUserAgent = userAgent;
        this.loginAttempts++;
        this.failedLoginAttempts = 0;
    }

    public void recordSuccessfulLogin(
            String ipAddress,
            String userAgent,
            String deviceId,
            String country,
            String city,
            Instant now
    ) {
        this.lastLogin          = now;
        this.lastLoginIp        = ipAddress;
        this.lastLoginUserAgent = userAgent;
        this.loginAttempts++;
        this.failedLoginAttempts = 0;
        getOrCreateSecurityMetadata().login()
                .recordSuccess(now, ipAddress, deviceId, country, city);
    }

    public void recordFailedLogin(Instant now) {
        this.failedLoginAttempts++;
        getOrCreateSecurityMetadata().login().recordFailed(now);
    }

    // =========================================================================
    // LOCKING
    // =========================================================================

    public boolean shouldBeTemporarilyLocked(Instant now, int threshold) {
        return getOrCreateSecurityMetadata().login().exceededThreshold(threshold)
                || getOrCreateSecurityMetadata().locking().isTemporarilyLocked(now);
    }

    public void applyTemporaryLock(
            Instant now,
            Duration duration,
            String reason,
            SecurityMetadata.LockType type
    ) {
        getOrCreateSecurityMetadata().locking().apply(now, duration, reason, type);
    }

    public void lockAccount() {
        this.accountLocked = true;
        this.status        = UserStatus.LOCKED;
    }

    public void unlockAccount() {
        this.accountLocked       = false;
        if (this.status == UserStatus.LOCKED) this.status = UserStatus.ACTIVE;
        this.failedLoginAttempts = 0;
    }

    // =========================================================================
    // PASSWORD HISTORY
    // =========================================================================

    public void addPasswordToHistory(
            String passwordHash,
            UserPasswordHistory.PasswordHashAlgorithm algorithm,
            UserPasswordHistory.PasswordChangeReason reason,
            String changedFromIp,
            Instant now
    ) {
        if (this.passwordHistoryEntries == null) this.passwordHistoryEntries = new ArrayList<>();
        passwordHistoryEntries.forEach(entry -> entry.setCurrent(false));

        UserPasswordHistory newEntry = UserPasswordHistory.builder()
                .passwordHash(passwordHash)
                .hashAlgorithm(algorithm)
                .changedAt(now)
                .changedFromIp(changedFromIp)
                .version((long) passwordHistoryEntries.size() + 1L)
                .reason(reason)
                .current(true)
                .build();

        passwordHistoryEntries.add(newEntry);
        while (passwordHistoryEntries.size() > 5) passwordHistoryEntries.remove(0);

        this.passwordLastChanged = now;
        getOrCreateSecurityMetadata().password().recordChange(now);
    }

    public boolean isPasswordRecentlyUsed(String plainPassword, int checkLastN) {
        if (passwordHistoryEntries == null || passwordHistoryEntries.isEmpty()) return false;
        return passwordHistoryEntries.stream()
                .limit(checkLastN)
                .anyMatch(entry -> entry.matches(plainPassword));
    }

    // =========================================================================
    // APPROVAL WORKFLOW
    // =========================================================================

    public void approve(String approvedBy, Instant now) {
        this.status        = UserStatus.ACTIVE;
        this.enabled       = true;
        this.approvedAt    = now;
        this.approvedBy    = approvedBy;
        this.approvalLevel = ApprovalLevel.APPROVED;
    }

    public void reject(String rejectedBy, String reason, Instant now) {
        this.status          = UserStatus.REJECTED;
        this.enabled         = false;
        this.rejectedAt      = now;
        this.rejectedBy      = rejectedBy;
        this.rejectionReason = reason;
        this.approvalLevel   = ApprovalLevel.REJECTED;
    }

    // =========================================================================
    // DISPLAY
    // =========================================================================

    public String getFullName() {
        if (firstName == null && lastName == null) return email;
        return String.format("%s %s",
                firstName != null ? firstName : "",
                lastName  != null ? lastName  : "").trim();
    }

    @Override
    public String toString() {
        return String.format("User[id=%s, email=%s, roles=%s, status=%s]",
                id, email, roleNames, status);
    }
}