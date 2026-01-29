package com.techStack.authSys.models.user;

import org.jetbrains.annotations.NotNull;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

/**
 * User Builder Factory
 *
 * Provides convenient factory methods to create users in different scenarios
 * with appropriate defaults and validation.
 *
 * Aligned with User model Firestore schema.
 */
public class UserFactory {

    private static final Clock DEFAULT_CLOCK = Clock.systemUTC();

    /* =========================
       Standard User Creation
       ========================= */

    /**
     * Create new user pending approval.
     * Default flow for user self-registration.
     */
    public static User createNewUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName
    ) {
        return createNewUser(email, firstName, lastName, DEFAULT_CLOCK);
    }

    public static User createNewUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull Clock clock
    ) {
        validateEmail(email);
        validateName(firstName, "First name");
        validateName(lastName, "Last name");

        Instant now = clock.instant();

        return User.builder()
                .email(email.toLowerCase().trim())
                .username(email.toLowerCase().trim())
                .firstName(firstName.trim())
                .lastName(lastName.trim())
                .status(UserStatus.PENDING_APPROVAL)
                .approvalLevel(ApprovalLevel.PENDING_L1)
                .enabled(false)
                .emailVerified(false)
                .accountLocked(false)
                .accountDisabled(false)
                .mfaRequired(false)
                .mfaEnabled(false)
                .forcePasswordChange(false)
                .roleNames(new ArrayList<>())
                .additionalPermissions(new ArrayList<>())
                .attributes(new HashMap<>())
                .passwordHistory(new ArrayList<>())
                .knownDeviceFingerprints(new HashSet<>())
                .loginAttempts(0)
                .failedLoginAttempts(0)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    /* =========================
       Pre-Approved User Creation
       ========================= */

    public static User createPreApprovedUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull Roles role
    ) {
        return createPreApprovedUser(email, firstName, lastName, role, DEFAULT_CLOCK);
    }

    public static User createPreApprovedUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull Roles role,
            @NotNull Clock clock
    ) {
        validateEmail(email);
        validateName(firstName, "First name");
        validateName(lastName, "Last name");

        Instant now = clock.instant();

        User user = User.builder()
                .email(email.toLowerCase().trim())
                .username(email.toLowerCase().trim())
                .firstName(firstName.trim())
                .lastName(lastName.trim())
                .status(UserStatus.ACTIVE)
                .approvalLevel(ApprovalLevel.NOT_REQUIRED)
                .enabled(true)
                .emailVerified(true)
                .accountLocked(false)
                .accountDisabled(false)
                .mfaRequired(false)
                .mfaEnabled(false)
                .forcePasswordChange(false)
                .roleNames(new ArrayList<>())
                .additionalPermissions(new ArrayList<>())
                .attributes(new HashMap<>())
                .passwordHistory(new ArrayList<>())
                .knownDeviceFingerprints(new HashSet<>())
                .loginAttempts(0)
                .failedLoginAttempts(0)
                .createdAt(now)
                .updatedAt(now)
                .build();

        user.addRole(role);
        return user;
    }

    /* =========================
       Administrative User Creation
       ========================= */

    public static User createAdminUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName
    ) {
        return createAdminUser(email, firstName, lastName, DEFAULT_CLOCK);
    }

    public static User createAdminUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull Clock clock
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, Roles.ADMIN, clock);
        user.setMfaRequired(true);
        user.setMfaEnabled(false);  // Must be set up by user
        return user;
    }

    public static User createManagerUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName
    ) {
        return createManagerUser(email, firstName, lastName, DEFAULT_CLOCK);
    }

    public static User createManagerUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull Clock clock
    ) {
        return createPreApprovedUser(email, firstName, lastName, Roles.MANAGER, clock);
    }

    /* =========================
       System User Creation
       ========================= */

    public static User createSuperAdmin(
            @NotNull String email,
            @NotNull String passwordHash
    ) {
        return createSuperAdmin(email, passwordHash, DEFAULT_CLOCK);
    }

    public static User createSuperAdmin(
            @NotNull String email,
            @NotNull String passwordHash,
            @NotNull Clock clock
    ) {
        validateEmail(email);

        Instant now = clock.instant();

        User user = User.builder()
                .email(email.toLowerCase().trim())
                .username(email.toLowerCase().trim())
                .firstName("System")
                .lastName("Administrator")
                .password(passwordHash)  // Transient field
                .status(UserStatus.ACTIVE)
                .approvalLevel(ApprovalLevel.NOT_REQUIRED)
                .enabled(true)
                .emailVerified(true)
                .accountLocked(false)
                .accountDisabled(false)
                .mfaRequired(true)
                .mfaEnabled(false)  // Must be set up
                .forcePasswordChange(false)
                .roleNames(new ArrayList<>())
                .additionalPermissions(new ArrayList<>())
                .attributes(new HashMap<>())
                .passwordHistory(new ArrayList<>())
                .knownDeviceFingerprints(new HashSet<>())
                .loginAttempts(0)
                .failedLoginAttempts(0)
                .createdAt(now)
                .updatedAt(now)
                .createdBy("SYSTEM")
                .build();

        user.addRole(Roles.SUPER_ADMIN);
        return user;
    }

    public static User createServiceAccount(
            @NotNull String serviceName,
            @NotNull String email
    ) {
        return createServiceAccount(serviceName, email, DEFAULT_CLOCK);
    }

    public static User createServiceAccount(
            @NotNull String serviceName,
            @NotNull String email,
            @NotNull Clock clock
    ) {
        validateEmail(email);
        validateName(serviceName, "Service name");

        Instant now = clock.instant();

        return User.builder()
                .email(email.toLowerCase().trim())
                .username("service_" + serviceName.toLowerCase().replaceAll("\\s+", "_"))
                .firstName("Service")
                .lastName(serviceName.trim())
                .status(UserStatus.ACTIVE)
                .approvalLevel(ApprovalLevel.NOT_REQUIRED)
                .enabled(true)
                .emailVerified(true)
                .accountLocked(false)
                .accountDisabled(false)
                .mfaRequired(false)
                .mfaEnabled(false)
                .forcePasswordChange(false)
                .roleNames(new ArrayList<>())
                .additionalPermissions(new ArrayList<>())
                .attributes(new HashMap<>())
                .passwordHistory(new ArrayList<>())
                .knownDeviceFingerprints(new HashSet<>())
                .loginAttempts(0)
                .failedLoginAttempts(0)
                .createdAt(now)
                .updatedAt(now)
                .createdBy("SYSTEM")
                .build();
    }

    /* =========================
       Specialized User Creation
       ========================= */

    public static User createOAuthUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull String provider,
            @NotNull String providerId
    ) {
        return createOAuthUser(email, firstName, lastName, provider, providerId, DEFAULT_CLOCK);
    }

    public static User createOAuthUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull String provider,
            @NotNull String providerId,
            @NotNull Clock clock
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, Roles.USER, clock);

        // Store OAuth info in attributes
        user.getAttributes().put("oauth_provider", provider);
        user.getAttributes().put("oauth_provider_id", providerId);

        return user;
    }

    public static User createInvitedUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull String invitedBy,
            @NotNull Roles role
    ) {
        return createInvitedUser(email, firstName, lastName, invitedBy, role, DEFAULT_CLOCK);
    }

    public static User createInvitedUser(
            @NotNull String email,
            @NotNull String firstName,
            @NotNull String lastName,
            @NotNull String invitedBy,
            @NotNull Roles role,
            @NotNull Clock clock
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, role, clock);
        user.setCreatedBy(invitedBy);
        user.setEmailVerified(false);  // Must verify email
        user.setForcePasswordChange(true);  // Must set password

        // Store invitation info
        user.getAttributes().put("invited_by", invitedBy);
        user.getAttributes().put("invited_at", clock.instant().toString());

        return user;
    }

    /* =========================
       Validation Helpers
       ========================= */

    private static void validateEmail(@NotNull String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be null or blank");
        }

        String trimmed = email.trim();
        if (!trimmed.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new IllegalArgumentException("Invalid email format: " + email);
        }
    }

    private static void validateName(@NotNull String name, @NotNull String fieldName) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException(fieldName + " cannot be null or blank");
        }

        if (name.trim().length() < 2) {
            throw new IllegalArgumentException(fieldName + " must be at least 2 characters");
        }
    }
}
