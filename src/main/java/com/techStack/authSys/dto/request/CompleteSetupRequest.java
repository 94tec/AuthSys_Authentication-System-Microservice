package com.techStack.authSys.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Complete Setup Request
 * Used in Step 3 of first-time setup
 */
public record CompleteSetupRequest(
        @NotBlank(message = "Verification token is required")
        String verificationToken
) {}
