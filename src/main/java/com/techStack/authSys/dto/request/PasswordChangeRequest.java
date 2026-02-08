package com.techStack.authSys.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Password Change Request DTO
 *
 * Request payload for user-initiated password changes.
 * Requires current password for verification.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordChangeRequest {

    @NotBlank(message = "Current password is required")
    private String currentPassword;

    @NotBlank(message = "New password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    private String newPassword;

    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;

    // Optional: Reason for change (for audit purposes)
    //private String changeReason;

    // Optional: IP address (usually extracted from request)
    //private String ipAddress;

    /**
     * Validate that new password differs from current password
     */
    public boolean passwordsAreDifferent() {
        return currentPassword != null && newPassword != null &&
                !currentPassword.equals(newPassword);
    }

    /**
     * Validate that new password matches confirmation
     */
    public boolean passwordsMatch() {
        return newPassword != null && newPassword.equals(confirmPassword);
    }

    /**
     * Validate all constraints
     */
    public boolean isValid() {
        return passwordsAreDifferent() && passwordsMatch();
    }
}