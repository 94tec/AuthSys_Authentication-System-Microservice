package com.techStack.authSys.dto.request;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Verify Login OTP Request DTO
 *
 * Specifically for login OTP verification (2FA).
 */
public record VerifyLoginOtpRequest(
        @NotBlank(message = "OTP is required")
        @Pattern(regexp = "^\\d{6}$", message = "OTP must be exactly 6 digits")
        String otp
) {}