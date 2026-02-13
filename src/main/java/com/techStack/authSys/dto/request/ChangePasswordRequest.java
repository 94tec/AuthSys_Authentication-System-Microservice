package com.techStack.authSys.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Password Change Request DTO
 *
 * Used for first-time password change and regular password updates.
 */
public record ChangePasswordRequest(
        @NotBlank(message = "New password is required")
        @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        @Pattern(
                regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
                message = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)"
        )
        String newPassword,

        @NotBlank(message = "Password confirmation is required")
        String confirmPassword
) {
    /**
     * Constructor validation - ensure passwords match
     */
    public ChangePasswordRequest {
        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("Passwords do not match");
        }
    }
}
