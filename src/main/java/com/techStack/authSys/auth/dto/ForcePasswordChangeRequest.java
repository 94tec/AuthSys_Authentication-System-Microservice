package com.techStack.authSys.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Force Password Change Request DTO
 *
 * Request payload for admin-initiated password changes.
 * Does not require current password (admin override).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ForcePasswordChangeRequest {

    @NotBlank(message = "User ID is required")
    private String userId;

    @NotBlank(message = "New password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    private String newPassword;

    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;

    // Reason for forced change (required for audit trail)
    @NotBlank(message = "Reason for password change is required")
    private String reason;

    // Whether to send notification email to user
    @Builder.Default
    private boolean sendNotification = true;

    // Whether to require password change on next login
    @Builder.Default
    private boolean requireChangeOnNextLogin = true;

    /**
     * Validate that passwords match
     */
    public boolean passwordsMatch() {
        return newPassword != null && newPassword.equals(confirmPassword);
    }
}