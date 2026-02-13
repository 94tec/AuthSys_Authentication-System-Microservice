package com.techStack.authSys.models.user;

import org.jetbrains.annotations.NotNull;

import java.time.Clock;
import java.time.Instant;
import java.util.*;

import static com.techStack.authSys.util.validation.ValidationUtils.validateEmail;
import static com.techStack.authSys.util.validation.ValidationUtils.validateName;

/**
 * User Factory
 *
 * Centralized user creation with Clock-based timestamps.
 */
public class UserFactory {

    private static final Clock DEFAULT_CLOCK = Clock.systemUTC();

    /* =========================
       Base Builder Initialization
       ========================= */

    /**
     * Common builder initialization for all user creation flows.
     */
    private static User.Builder baseBuilder(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull Clock clock,
            String message
    ) {
        validateEmail(email, message);
        validateName(firstName, "First name");
        validateName(lastName, "Last name");

        Instant now = clock.instant();

        return User.builder()
                .email(email.toLowerCase().trim())
                .firstName(firstName.trim())
                .lastName(lastName.trim())
                .username(email.toLowerCase().trim())
                .roleNames(new ArrayList<>())
                .additionalPermissions(new ArrayList<>())
                .attributes(new HashMap<>())
                .status(UserStatus.PENDING_APPROVAL)
                .enabled(false)
                .accountLocked(false)
                .accountDisabled(false)
                .emailVerified(false)
                .forcePasswordChange(false)
                .phoneVerified(false)
                .mfaEnabled(false)
                .mfaRequired(false)
                .loginAttempts(0)
                .failedLoginAttempts(0)
                .knownDeviceFingerprints("")
                .passwordHistoryEntries(new ArrayList<>())
                .createdAt(now)
                .updatedAt(now);
    }

    /* =========================
       Standard User Creation
       ========================= */

    public static User createNewUser(String email, String firstName, String lastName) {
        return createNewUser(email, firstName, lastName, DEFAULT_CLOCK, null);
    }

    public static User createNewUser(
            String email,
            String firstName,
            String lastName,
            Clock clock
    ) {
        return createNewUser(email, firstName, lastName, clock, null);
    }

    public static User createNewUser(
            String email,
            String firstName,
            String lastName,
            Clock clock,
            String message
    ) {
        return baseBuilder(email, firstName, lastName, clock, message)
                .status(UserStatus.PENDING_APPROVAL)
                .approvalLevel(ApprovalLevel.PENDING_L1)
                .build();
    }

    /* =========================
       Pre-Approved User Creation
       ========================= */

    public static User createPreApprovedUser(
            String email,
            String firstName,
            String lastName,
            Roles role
    ) {
        return createPreApprovedUser(email, firstName, lastName, role, DEFAULT_CLOCK, null);
    }

    public static User createPreApprovedUser(
            String email,
            String firstName,
            String lastName,
            Roles role,
            Clock clock
    ) {
        return createPreApprovedUser(email, firstName, lastName, role, clock, null);
    }

    public static User createPreApprovedUser(
            String email,
            String firstName,
            String lastName,
            Roles role,
            Clock clock,
            String message
    ) {
        User user = baseBuilder(email, firstName, lastName, clock, message)
                .status(UserStatus.ACTIVE)
                .approvalLevel(ApprovalLevel.NOT_REQUIRED)
                .enabled(true)
                .emailVerified(true)
                .build();

        user.addRole(role);
        return user;
    }

    /* =========================
       Administrative Users
       ========================= */

    /**
     * Create admin user with default clock
     */
    public static User createAdminUser(String email, String firstName, String lastName) {
        return createAdminUser(email, firstName, lastName, DEFAULT_CLOCK, null);
    }

    /**
     * Create admin user with custom clock
     */
    public static User createAdminUser(
            String email,
            String firstName,
            String lastName,
            Clock clock
    ) {
        return createAdminUser(email, firstName, lastName, clock, null);
    }

    /**
     * Create admin user with custom clock and validation message
     */
    public static User createAdminUser(
            String email,
            String firstName,
            String lastName,
            Clock clock,
            String message
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, Roles.ADMIN, clock, message);
        user.setMfaRequired(true);
        return user;
    }

    /* =========================
       Manager Users
       ========================= */

    public static User createManagerUser(String email, String firstName, String lastName) {
        return createManagerUser(email, firstName, lastName, DEFAULT_CLOCK, null);
    }

    public static User createManagerUser(
            String email,
            String firstName,
            String lastName,
            Clock clock
    ) {
        return createManagerUser(email, firstName, lastName, clock, null);
    }

    public static User createManagerUser(
            String email,
            String firstName,
            String lastName,
            Clock clock,
            String message
    ) {
        return createPreApprovedUser(email, firstName, lastName, Roles.MANAGER, clock, message);
    }

    /* =========================
       Super Admin Users
       ========================= */

    public static User createSuperAdminUser(String email, String passwordHash) {
        return createSuperAdmin(email, passwordHash, DEFAULT_CLOCK, null);
    }

    public static User createSuperAdmin(
            String email,
            String passwordHash,
            Clock clock
    ) {
        return createSuperAdmin(email, passwordHash, clock, null);
    }

    public static User createSuperAdmin(
            String email,
            String passwordHash,
            Clock clock,
            String message
    ) {
        validateEmail(email, message);

        User user = baseBuilder(email, "System", "Administrator", clock, message)
                .status(UserStatus.ACTIVE)
                .approvalLevel(ApprovalLevel.NOT_REQUIRED)
                .enabled(true)
                .emailVerified(true)
                .password(passwordHash)
                .mfaRequired(true)
                .createdBy("SYSTEM")
                .build();

        user.addRole(Roles.SUPER_ADMIN);
        return user;
    }

    /* =========================
       Service Accounts
       ========================= */

    public static User createServiceAccount(String serviceName, String email) {
        return createServiceAccount(serviceName, email, DEFAULT_CLOCK, null);
    }

    public static User createServiceAccount(
            String serviceName,
            String email,
            Clock clock
    ) {
        return createServiceAccount(serviceName, email, clock, null);
    }

    public static User createServiceAccount(
            String serviceName,
            String email,
            Clock clock,
            String message
    ) {
        validateName(serviceName, "Service name");

        User user = baseBuilder(email, "Service", serviceName, clock, message)
                .status(UserStatus.ACTIVE)
                .approvalLevel(ApprovalLevel.NOT_REQUIRED)
                .enabled(true)
                .emailVerified(true)
                .username("service_" + serviceName.toLowerCase().replaceAll("\\s+", "_"))
                .mfaRequired(false)
                .createdBy("SYSTEM")
                .build();

        user.addRole(Roles.MANAGER);
        return user;
    }

    /* =========================
       OAuth Users
       ========================= */

    public static User createOAuthUser(
            String email,
            String firstName,
            String lastName,
            String provider,
            String providerId
    ) {
        return createOAuthUser(email, firstName, lastName, provider, providerId, DEFAULT_CLOCK, null);
    }

    public static User createOAuthUser(
            String email,
            String firstName,
            String lastName,
            String provider,
            String providerId,
            Clock clock
    ) {
        return createOAuthUser(email, firstName, lastName, provider, providerId, clock, null);
    }

    public static User createOAuthUser(
            String email,
            String firstName,
            String lastName,
            String provider,
            String providerId,
            Clock clock,
            String message
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, Roles.USER, clock, message);
        user.getAttributes().put("oauth_provider", provider);
        user.getAttributes().put("oauth_provider_id", providerId);
        return user;
    }

    /* =========================
       Invited Users
       ========================= */

    public static User createInvitedUser(
            String email,
            String firstName,
            String lastName,
            String invitedBy,
            Roles role
    ) {
        return createInvitedUser(email, firstName, lastName, invitedBy, role, DEFAULT_CLOCK, null);
    }

    public static User createInvitedUser(
            String email,
            String firstName,
            String lastName,
            String invitedBy,
            Roles role,
            Clock clock
    ) {
        return createInvitedUser(email, firstName, lastName, invitedBy, role, clock, null);
    }

    public static User createInvitedUser(
            String email,
            String firstName,
            String lastName,
            String invitedBy,
            Roles role,
            Clock clock,
            String message
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, role, clock, message);
        user.setCreatedBy(invitedBy);
        user.setEmailVerified(false);
        user.setForcePasswordChange(true);
        user.getAttributes().put("invited_by", invitedBy);
        user.getAttributes().put("invited_at", clock.instant().toString());
        return user;
    }

    /* =========================
       Utility Methods
       ========================= */

    public static User withRoles(User user, Roles... roles) {
        for (Roles role : roles) {
            user.addRole(role);
        }
        return user;
    }

    public static User withRole(User user, Roles role) {
        user.addRole(role);
        return user;
    }

    public static User withPermissions(User user, String... permissions) {
        for (String permission : permissions) {
            user.addPermission(permission);
        }
        return user;
    }

    public static User withAttributes(User user, Map<String, Object> attributes) {
        user.getAttributes().putAll(attributes);
        return user;
    }

    /* =========================
       Builder for complex user creation
       ========================= */

    public static class FactoryBuilder {
        private String email;
        private String firstName;
        private String lastName;
        private String phoneNumber;
        private String identityNo;
        private final List<Roles> roles = new ArrayList<>();
        private final List<String> permissions = new ArrayList<>();
        private UserStatus status = UserStatus.PENDING_APPROVAL;
        private ApprovalLevel approvalLevel = ApprovalLevel.PENDING_L1;
        private boolean emailVerified = false;
        private boolean phoneVerified = false;
        private boolean mfaEnabled = false;
        private boolean mfaRequired = false;
        private String createdBy;
        private final Map<String, Object> attributes = new HashMap<>();
        private Clock clock = DEFAULT_CLOCK;
        private String message;

        public FactoryBuilder email(String email) {
            this.email = email;
            return this;
        }

        public FactoryBuilder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        public FactoryBuilder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        public FactoryBuilder phoneNumber(String phoneNumber) {
            this.phoneNumber = phoneNumber;
            return this;
        }

        public FactoryBuilder identityNo(String identityNo) {
            this.identityNo = identityNo;
            return this;
        }

        public FactoryBuilder withRole(Roles role) {
            this.roles.add(role);
            return this;
        }

        public FactoryBuilder withRoles(Roles... roles) {
            this.roles.addAll(Arrays.asList(roles));
            return this;
        }

        public FactoryBuilder withPermission(String permission) {
            this.permissions.add(permission);
            return this;
        }

        public FactoryBuilder withPermissions(String... permissions) {
            this.permissions.addAll(Arrays.asList(permissions));
            return this;
        }

        public FactoryBuilder status(UserStatus status) {
            this.status = status;
            return this;
        }

        public FactoryBuilder approvalLevel(ApprovalLevel approvalLevel) {
            this.approvalLevel = approvalLevel;
            return this;
        }

        public FactoryBuilder emailVerified(boolean verified) {
            this.emailVerified = verified;
            return this;
        }

        public FactoryBuilder phoneVerified(boolean verified) {
            this.phoneVerified = verified;
            return this;
        }

        public FactoryBuilder mfaEnabled(boolean enabled) {
            this.mfaEnabled = enabled;
            return this;
        }

        public FactoryBuilder mfaRequired(boolean required) {
            this.mfaRequired = required;
            return this;
        }

        public FactoryBuilder createdBy(String createdBy) {
            this.createdBy = createdBy;
            return this;
        }

        public FactoryBuilder attribute(String key, Object value) {
            this.attributes.put(key, value);
            return this;
        }

        public FactoryBuilder attributes(Map<String, Object> attributes) {
            this.attributes.putAll(attributes);
            return this;
        }

        public FactoryBuilder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public FactoryBuilder message(String message) {
            this.message = message;
            return this;
        }

        public User build() {
            validateEmail(email, message);
            validateName(firstName, "First name");
            validateName(lastName, "Last name");

            Instant now = clock.instant();

            User.Builder builder = User.builder()
                    .email(email.toLowerCase().trim())
                    .firstName(firstName.trim())
                    .lastName(lastName.trim())
                    .username(email.toLowerCase().trim())
                    .phoneNumber(phoneNumber)
                    .identityNo(identityNo)
                    .status(status)
                    .approvalLevel(approvalLevel)
                    .enabled(status == UserStatus.ACTIVE)
                    .emailVerified(emailVerified)
                    .phoneVerified(phoneVerified)
                    .mfaEnabled(mfaEnabled)
                    .mfaRequired(mfaRequired)
                    .createdBy(createdBy)
                    .attributes(attributes)
                    .createdAt(now)
                    .updatedAt(now);

            User user = builder.build();

            for (Roles role : roles) {
                user.addRole(role);
            }

            for (String permission : permissions) {
                user.addPermission(permission);
            }

            return user;
        }
    }

    public static FactoryBuilder builder() {
        return new FactoryBuilder();
    }
}