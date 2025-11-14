package com.techStack.authSys.models;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.annotation.PropertyName;
import com.google.cloud.spring.data.firestore.Document;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.service.RoleAssignmentService;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collectionName = "users")
public class User implements UserDetails {

    //@DocumentId
    private String id;

    private String firstName;
    private String lastName;
    private String email;
    private String username;
    private String identityNo;
    private String phoneNumber;
    private String password;

    // user password history
    private List<UserPasswordHistory> passwordHistory;

    // Role & Permission Management
    @PropertyName("roles")
    private List<String> roleNames = new ArrayList<>();
    //private Permissions permissions;
    private List<String> permissions;
    private Roles requestedRole; // During registration
    private String department;   // For ABAC
    private Status status;       // ACTIVE, PENDING_APPROVAL, etc.

    // Authorities (injected by UserDetailsService)
    private Collection<? extends GrantedAuthority> authorities;

    // Multi-Factor Authentication
    private String otpSecret;
    private boolean mfaRequired;

    //admin setup
    private String createdBy;
    private Instant createdAt;
    private  Instant updatedAt;
    private boolean forcePasswordChange = false;
    private boolean accountDisabled;
    // Account State
    private boolean enabled;
    private boolean accountLocked;
    private boolean emailVerified;

    // Login and Security Tracking
    private int loginAttempts;
    private int failedLoginAttempts;
    private Instant lastLogin;
    private Timestamp lastLoginTimestamp;
    private String lastLoginIp;
    private String lastLoginIpAddress;
    private String userAgent;

    // Profile Details
    private String profilePictureUrl;
    private String bio;
    private String userProfileId;

    // Verification & Tokens
    private String verificationToken;
    private String verificationTokenHash;
    private Instant verificationTokenExpiresAt;
    private String passwordResetToken;
    private String lastPasswordChangeDate;
    private String deviceFingerprint;

    // Approval tracking fields
    //private String approvalLevel;      // ApprovalLevel enum as string
    //private Instant approvedAt;        // When was account approved
    private RoleAssignmentService.ApprovalLevel approvalLevel; // <--- FIX: Use the actual enum type
    private Instant approvedAt;
    private String approvedBy;         // Who approved (admin email/id)

    private String rejectionReason;
    private String rejectedBy;
    private String rejectedAt;
    private String restoredBy;
    private String restoredAt;


    // Spring Security fields
    @PropertyName("account_non_locked")
    private boolean accountNonLocked;

    @PropertyName("credentials_non_expired")
    private boolean credentialsNonExpired;

    @PropertyName("account_non_expired")
    private boolean accountNonExpired;

    // -------------------------------
    // Role Utility Methods
    // ---
    // ----------------------------

    public Set<Roles> getRoles() {
        if (roleNames == null) return new HashSet<>();
        return roleNames.stream()
                .map(Roles::valueOf)
                .collect(Collectors.toSet());
    }

    // Modified addRole to work with List storage
    public void addRole(Roles role) {
        if (this.roleNames == null) this.roleNames = new ArrayList<>();
        if (!this.roleNames.contains(role.name())) {
            this.roleNames.add(role.name());
        }
    }

    // Modified removeRole to work with List storage
    public void removeRole(Roles role) {
        if (this.roleNames != null) {
            this.roleNames.remove(role.name());
        }
    }

    public boolean hasRole(Roles role) {
        return this.roleNames != null && this.roleNames.contains(role.name()); // Check if the role name exists
    }

    public boolean hasHigherPrivilegesThan(Roles otherRole) {
        return getRoles().stream().anyMatch(r -> r.hasHigherPrivilegesThan(otherRole));
    }
    // inside com.techStack.authSys.models.User
    public UserRecord toUserRecord() {
        // NOTE: UserRecord is normally returned from FirebaseAuth.getUserBy...()
        // You cannot build a UserRecord directly. It's immutable and has no public constructors.
        throw new UnsupportedOperationException("UserRecord is a Firebase SDK object and cannot be manually created.");
    }
    public Optional<RoleAssignmentService.ApprovalLevel> getApprovalLevel() {
        return Optional.ofNullable(approvalLevel);
    }

    // -------------------------------
    // UserDetails Interface Overrides
    // -------------------------------

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // ... (No change needed)
        return this.authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    // -------------------------------
    // Account Status Enum
    // -------------------------------
    public enum Status {
        ACTIVE,
        REJECTED,
        PENDING_APPROVAL,
        DISABLED,
        SUSPENDED
    }
}