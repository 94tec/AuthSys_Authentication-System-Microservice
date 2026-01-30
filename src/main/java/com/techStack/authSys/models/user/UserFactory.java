package com.techStack.authSys.models.user;

import com.techStack.authSys.models.security.SecurityMetadata;
import org.jetbrains.annotations.NotNull;

import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * User Factory
 *
 * Centralized user creation with Clock-based timestamps.
 * Single Responsibility: Only handles user creation.
 * Security/risk helpers belong in SecurityMetadata or User.
 */
public class UserFactory {

    private static final Clock DEFAULT_CLOCK = Clock.systemUTC();

    /* =========================
       Base Builder Initialization
       ========================= */

    /**
     * Common builder initialization for all user creation flows.
     * All timestamps come from Clock for testability.
     */
    private static User.UserBuilder baseBuilder(
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
                .passwordHistoryEntries(new ArrayList<>())
                .knownDeviceFingerprints(new HashSet<>())
                .loginAttempts(0)
                .failedLoginAttempts(0)
                .createdAt(now)
                .updatedAt(now);
    }

    /* =========================
       Standard User Creation
       ========================= */

    public static User createNewUser(String email, String firstName, String lastName) {
        return createNewUser(email, firstName, lastName, DEFAULT_CLOCK);
    }

    public static User createNewUser(
            String email,
            String firstName,
            String lastName,
            Clock clock
    ) {
        return baseBuilder(email, firstName, lastName, clock)
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
        return createPreApprovedUser(email, firstName, lastName, role, DEFAULT_CLOCK);
    }

    public static User createPreApprovedUser(
            String email,
            String firstName,
            String lastName,
            Roles role,
            Clock clock
    ) {
        User user = baseBuilder(email, firstName, lastName, clock)
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

    public static User createAdminUser(String email, String firstName, String lastName) {
        return createAdminUser(email, firstName, lastName, DEFAULT_CLOCK);
    }

    public static User createAdminUser(
            String email,
            String firstName,
            String lastName,
            Clock clock
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, Roles.ADMIN, clock);
        user.setMfaRequired(true);
        return user;
    }

    public static User createManagerUser(String email, String firstName, String lastName) {
        return createManagerUser(email, firstName, lastName, DEFAULT_CLOCK);
    }

    public static User createManagerUser(
            String email,
            String firstName,
            String lastName,
            Clock clock
    ) {
        return createPreApprovedUser(email, firstName, lastName, Roles.MANAGER, clock);
    }

    /* =========================
       System Users
       ========================= */

    public static User createSuperAdmin(String email, String passwordHash) {
        return createSuperAdmin(email, passwordHash, DEFAULT_CLOCK);
    }

    public static User createSuperAdmin(
            String email,
            String passwordHash,
            Clock clock
    ) {
        validateEmail(email);

        User user = baseBuilder(email, "System", "Administrator", clock)
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

    public static User createServiceAccount(String serviceName, String email) {
        return createServiceAccount(serviceName, email, DEFAULT_CLOCK);
    }

    public static User createServiceAccount(
            String serviceName,
            String email,
            Clock clock
    ) {
        validateName(serviceName, "Service name");

        return baseBuilder(email, "Service", serviceName, clock)
                .status(UserStatus.ACTIVE)
                .approvalLevel(ApprovalLevel.NOT_REQUIRED)
                .enabled(true)
                .emailVerified(true)
                .username("service_" + serviceName.toLowerCase().replaceAll("\\s+", "_"))
                .mfaRequired(false)
                .createdBy("SYSTEM")
                .build();
    }

    /* =========================
       Specialized Users
       ========================= */

    public static User createOAuthUser(
            String email,
            String firstName,
            String lastName,
            String provider,
            String providerId
    ) {
        return createOAuthUser(email, firstName, lastName, provider, providerId, DEFAULT_CLOCK);
    }

    public static User createOAuthUser(
            String email,
            String firstName,
            String lastName,
            String provider,
            String providerId,
            Clock clock
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, Roles.USER, clock);
        user.getAttributes().put("oauth_provider", provider);
        user.getAttributes().put("oauth_provider_id", providerId);
        return user;
    }

    public static User createInvitedUser(
            String email,
            String firstName,
            String lastName,
            String invitedBy,
            Roles role
    ) {
        return createInvitedUser(email, firstName, lastName, invitedBy, role, DEFAULT_CLOCK);
    }

    public static User createInvitedUser(
            String email,
            String firstName,
            String lastName,
            String invitedBy,
            Roles role,
            Clock clock
    ) {
        User user = createPreApprovedUser(email, firstName, lastName, role, clock);
        user.setCreatedBy(invitedBy);
        user.setEmailVerified(false);
        user.setForcePasswordChange(true);
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