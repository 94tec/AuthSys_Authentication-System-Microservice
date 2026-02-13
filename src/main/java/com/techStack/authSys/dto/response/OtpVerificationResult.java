package com.techStack.authSys.dto.response;// ============================================================================
// OtpVerificationResult.java
// ============================================================================

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * OTP Verification Result DTO
 *
 * Using class for WebFlux compatibility.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtpVerificationResult {
    private boolean valid;
    private boolean expired;
    private boolean attemptsExceeded;
    private int remainingAttempts;
    private String message;

    public static OtpVerificationResult success() {
        return new OtpVerificationResult(true, false, false, 0, "OTP verified successfully");
    }

    public static OtpVerificationResult invalid(int remaining) {
        return new OtpVerificationResult(false, false, false, remaining,
                String.format("Invalid OTP. %d attempts remaining.", remaining));
    }

    public static OtpVerificationResult expired() {
        return new OtpVerificationResult(false, true, false, 0,
                "OTP has expired. Please request a new one.");
    }

    public static OtpVerificationResult attemptsExceeded() {
        return new OtpVerificationResult(false, false, true, 0,
                "Maximum attempts exceeded. Please request a new OTP.");
    }
}