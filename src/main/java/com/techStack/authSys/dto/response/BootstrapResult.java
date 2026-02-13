package com.techStack.authSys.dto.response;

/**
 * Result DTO for bootstrap operations.
 * Provides clear status information about what happened during bootstrap.
 */
public record BootstrapResult(
        boolean created,
        boolean alreadyExists,
        boolean bootstrapMarkedComplete,
        boolean emailSent,
        String userId,
        String message,
        boolean requiresFirstTimeSetup
) {
    public static BootstrapResult created(String userId, boolean emailSent) {
        return new BootstrapResult(
                true,
                false,
                true,
                emailSent,
                userId,
                emailSent
                        ? "Super Admin created successfully. Check email for credentials."
                        : "Super Admin created successfully. Email delivery failed - check logs for password.",
                true
        );
    }

    public static BootstrapResult alreadyExists(String userId) {
        return new BootstrapResult(
                false,
                true,
                true,
                false,
                userId,
                "Super Admin already exists. Bootstrap marked complete.",
                false
        );
    }
}
