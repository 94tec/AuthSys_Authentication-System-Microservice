package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * OTP Verification Result DTO
 *
 * Enhanced with verification token support for FirstTimeLoginSetupService
 * Using class for WebFlux compatibility.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtpVerificationResult {
    private boolean valid;
    private boolean expired;
    private boolean attemptsExceeded;
    private int remainingAttempts;
    private String message;

    // ⭐ NEW: Fields for FirstTimeLoginSetupService Step 2
    private String verificationToken;  // Token returned after OTP verified
    private Long expiresInSeconds;     // Token expiry (5 minutes = 300 seconds)

    // Static factory methods
    public static OtpVerificationResult success() {
        return OtpVerificationResult.builder()
                .valid(true)
                .expired(false)
                .attemptsExceeded(false)
                .remainingAttempts(0)
                .message("OTP verified successfully")
                .build();
    }

    public static OtpVerificationResult invalid(int remaining) {
        return OtpVerificationResult.builder()
                .valid(false)
                .expired(false)
                .attemptsExceeded(false)
                .remainingAttempts(remaining)
                .message(String.format("Invalid OTP. %d attempts remaining.", remaining))
                .build();
    }

    public static OtpVerificationResult expired() {
        return OtpVerificationResult.builder()
                .valid(false)
                .expired(true)
                .attemptsExceeded(false)
                .remainingAttempts(0)
                .message("OTP has expired. Please request a new one.")
                .build();
    }

    public static OtpVerificationResult attemptsExceeded() {
        return OtpVerificationResult.builder()
                .valid(false)
                .expired(false)
                .attemptsExceeded(true)
                .remainingAttempts(0)
                .message("Maximum attempts exceeded. Please request a new OTP.")
                .build();
    }

    // ✅ Lombok generates both isValid() and valid() getters
    // No need to manually add them
}