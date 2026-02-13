package com.techStack.authSys.dto.request;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Request Login OTP Request DTO
 *
 * Used to request a login OTP (for manual trigger or resend).
 */
public record RequestLoginOtpRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email
) {}
