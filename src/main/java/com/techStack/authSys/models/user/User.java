package com.techStack.authSys.models.user;

import com.techStack.authSys.models.security.SecurityMetadata;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * User domain model — pure business logic, no persistence annotations.
 *
 * Assembled by UserAssembler from:
 *   UserDocument  (Firestore) + UserEntity (PostgreSQL)
 *
 * Implements UserDetails for Spring Security integration.
 * SecurityMetadata is safe here — it's only used in memory, never persisted
 * directly. UserDocument stores the equivalent fields as flat primitives.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {

    // =========================================================================
    // IDENTITY
    // =========================================================================

    private String id;                          // Firebase UID
    private String firebaseUid;
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

    @Builder.Default
    private transient String password = null;

    // =========================================================================
    // ROLES & PERMISSIONS
    // =========================================================================

    @Builder.Default
    private List<String> roleNames = new ArrayList<>();

    @Builder.Default
    private List<String> additionalPermissions = new ArrayList<>();

    @Builder.Default
    private Set<String> customPermissions = new HashSet<>();

    @Builder.Default
    private List<String> requestedRoleNames = new ArrayList<>();

    @Builder.Default
    private Map<String, String> attributes = new HashMap<>();

    // =========================================================================
    // ACCOUNT STATUS
    // =========================================================================

    @Builder.Default
    private UserStatus status = UserStatus.PENDING_APPROVAL;

    @Builder.Default
    private boolean enabled = false;

    @Builder.Default
    private boolean accountLocked = false;

    @Builder.Default
    private boolean accountDisabled = false;

    @Builder.Default
    private boolean emailVerified = false;

    @Builder.Default
    private boolean phoneVerified = false;

    @Builder.Default
    private boolean forcePasswordChange = false;

    // =========================================================================
    // APPROVAL WORKFLOW
    // =========================================================================

    private ApprovalLevel approvalLevel;
    private Instant approvedAt;
    private String approvedBy;
    private Instant rejectedAt;
    private String rejectedBy;
    private String rejectionReason;

    // =========================================================================
    // SECURITY — SecurityMetadata safe here (in-memory only)
    // =========================================================================

    private SecurityMetadata securityMetadata;

    @Builder.Default
    private List<UserPasswordHistory> passwordHistoryEntries = new ArrayList<>();

    @Builder.Default
    private boolean mfaEnabled = false;

    @Builder.Default
    private boolean mfaRequired = false;

    private String otpSecret;

    @Builder.Default
    private int loginAttempts = 0;

    @Builder.Default
    private int failedLoginAttempts = 0;

    private Instant lastLogin;
    private String lastLoginIp;
    private String lastLoginUserAgent;

    private Instant passwordLastChanged;
    private Instant passwordExpiresAt;

    @Builder.Default
    private boolean firstTimeSetupCompleted = false;
    private Instant firstTimeSetupCompletedAt;

    @Builder.Default
    private boolean temporaryPasswordLocked = false;
    private Instant temporaryPasswordLockedAt;

    private String passwordResetTokenHash;
    private Instant passwordResetTokenExpiresAt;
    private String verificationTokenHash;
    private Instant verificationTokenExpiresAt;

    // =========================================================================
    // AUDIT
    // =========================================================================

    private Instant createdAt;
    private String createdBy;
    private Instant updatedAt;

    // =========================================================================
    // SPRING SECURITY
    // =========================================================================

    @Builder.Default
    private transient Collection<? extends GrantedAuthority> authorities = null;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.authorities != null) return this.authorities;

        Set<GrantedAuthority> granted = new HashSet<>();

        if (roleNames != null) {
            roleNames.forEach(role ->
                    granted.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }

        if (additionalPermissions != null) {
            additionalPermissions.forEach(perm ->
                    granted.add(new SimpleGrantedAuthority(perm)));
        }

        if (customPermissions != null) {
            customPermissions.forEach(perm ->
                    granted.add(new SimpleGrantedAuthority(perm)));
        }

        return granted;
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

    public Roles getPrimaryRole() {
        if (roleNames == null || roleNames.isEmpty()) return Roles.USER;

        return Arrays.asList(
                        Roles.SUPER_ADMIN, Roles.ADMIN, Roles.DESIGNER,
                        Roles.MANAGER, Roles.USER, Roles.GUEST)
                .stream()
                .filter(r -> roleNames.contains(r.name()))
                .findFirst()
                .orElse(Roles.USER);
    }

    public Set<Roles> getRoles() {
        if (roleNames == null || roleNames.isEmpty()) return Set.of(Roles.USER);
        return roleNames.stream()
                .map(name -> {
                    Optional<Roles> r = Roles.fromName(name);
                    if (r.isEmpty()) {
                        org.slf4j.LoggerFactory.getLogger(User.class)
                                .warn("Unknown role '{}' for user {} — skipping", name, email);
                    }
                    return r;
                })
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toSet());
    }

    public Roles getHighestPriorityRole() {
        return getRoles().stream()
                .max(Comparator.comparingInt(Roles::getLevel))
                .orElse(Roles.USER);
    }

    public void addRole(Roles role) {
        if (roleNames == null) roleNames = new ArrayList<>();
        if (!roleNames.contains(role.name())) roleNames.add(role.name());
    }

    public void removeRole(Roles role) {
        if (roleNames != null) roleNames.remove(role.name());
    }

    public boolean hasRole(Roles role) {
        return roleNames != null && roleNames.contains(role.name());
    }

    public boolean hasAnyRole(Roles... roles) {
        if (roleNames == null) return false;
        return Arrays.stream(roles).anyMatch(r -> roleNames.contains(r.name()));
    }

    public boolean hasHigherPrivilegesThan(Roles other) {
        return getRoles().stream().anyMatch(r -> r.getLevel() > other.getLevel());
    }

    public Set<Roles> getRequestedRoles() {
        if (requestedRoleNames == null || requestedRoleNames.isEmpty()) return Set.of(Roles.USER);
        return requestedRoleNames.stream()
                .map(Roles::fromName)
                .flatMap(Optional::stream)
                .collect(Collectors.toSet());
    }

    public void setRequestedRoles(Set<Roles> roles) {
        this.requestedRoleNames = roles == null ? new ArrayList<>() :
                roles.stream().map(Roles::name).collect(Collectors.toList());
    }

    // =========================================================================
    // PERMISSION MANAGEMENT
    // =========================================================================

    public void addPermission(String permission) {
        if (additionalPermissions == null) additionalPermissions = new ArrayList<>();
        if (!additionalPermissions.contains(permission)) additionalPermissions.add(permission);
    }

    public void addCustomPermission(String permission) {
        if (customPermissions == null) customPermissions = new HashSet<>();
        customPermissions.add(permission);
    }

    public void removeCustomPermission(String permission) {
        if (customPermissions != null) customPermissions.remove(permission);
    }

    public boolean hasCustomPermission(String permission) {
        return customPermissions != null && customPermissions.contains(permission);
    }

    public Set<String> getAllPermissions() {
        Set<String> perms = new HashSet<>();
        if (additionalPermissions != null) perms.addAll(additionalPermissions);
        if (customPermissions != null)     perms.addAll(customPermissions);
        return perms;
    }

    // =========================================================================
    // ACCOUNT STATE
    // =========================================================================

    public boolean isActive() {
        return status == UserStatus.ACTIVE && enabled && !accountLocked && !accountDisabled;
    }

    public boolean isPendingApproval() {
        return status == UserStatus.PENDING_APPROVAL;
    }

    public boolean isPasswordExpired(Clock clock) {
        return passwordExpiresAt != null && clock.instant().isAfter(passwordExpiresAt);
    }

    public boolean needsPasswordChange(Clock clock) {
        return forcePasswordChange || isPasswordExpired(clock);
    }

    public boolean hasFirebaseAccount() {
        return firebaseUid != null && !firebaseUid.isBlank();
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

    public void recordLogin(String ip, String userAgent, Instant now) {
        this.lastLogin          = now;
        this.lastLoginIp        = ip;
        this.lastLoginUserAgent = userAgent;
        this.loginAttempts++;
        this.failedLoginAttempts = 0;
    }

    public void recordSuccessfulLogin(String ip, String userAgent,
                                      String deviceId, String country, String city, Instant now) {
        recordLogin(ip, userAgent, now);
        getOrCreateSecurityMetadata().login()
                .recordSuccess(now, ip, deviceId, country, city);
    }

    public void recordFailedLogin(Instant now) {
        this.failedLoginAttempts++;
        getOrCreateSecurityMetadata().login().recordFailed(now);
    }

    public boolean shouldBeTemporarilyLocked(Instant now, int threshold) {
        return getOrCreateSecurityMetadata().login().exceededThreshold(threshold)
                || getOrCreateSecurityMetadata().locking().isTemporarilyLocked(now);
    }

    public void applyTemporaryLock(Instant now, Duration duration,
                                   String reason, SecurityMetadata.LockType type) {
        getOrCreateSecurityMetadata().locking().apply(now, duration, reason, type);
    }

    public void lockAccount() {
        this.accountLocked = true;
        this.status        = UserStatus.LOCKED;
    }

    public void unlockAccount() {
        this.accountLocked       = false;
        if (status == UserStatus.LOCKED) this.status = UserStatus.ACTIVE;
        this.failedLoginAttempts = 0;
    }

    // =========================================================================
    // PASSWORD HISTORY
    // =========================================================================

    public void addPasswordToHistory(String hash,
                                     UserPasswordHistory.PasswordHashAlgorithm algorithm,
                                     UserPasswordHistory.PasswordChangeReason reason,
                                     String ip, Instant now) {

        if (passwordHistoryEntries == null) passwordHistoryEntries = new ArrayList<>();
        passwordHistoryEntries.forEach(e -> e.setCurrent(false));

        passwordHistoryEntries.add(UserPasswordHistory.builder()
                .passwordHash(hash)
                .hashAlgorithm(algorithm)
                .changedAt(now)
                .changedFromIp(ip)
                .version((long) passwordHistoryEntries.size() + 1L)
                .reason(reason)
                .current(true)
                .build());

        while (passwordHistoryEntries.size() > 5) passwordHistoryEntries.remove(0);
        this.passwordLastChanged = now;
        getOrCreateSecurityMetadata().password().recordChange(now);
    }

    public boolean isPasswordRecentlyUsed(String plainPassword, int checkLastN) {
        if (passwordHistoryEntries == null || passwordHistoryEntries.isEmpty()) return false;
        return passwordHistoryEntries.stream()
                .limit(checkLastN)
                .anyMatch(e -> e.matches(plainPassword));
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