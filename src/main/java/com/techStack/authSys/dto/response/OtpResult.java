package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

// ============================================================================
// OtpResult.java
// ============================================================================

/**
 * OTP Result DTO
 *
 * Using class instead of record to avoid WebFlux/Reactive compilation issues.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtpResult {
    private boolean sent;
    private boolean rateLimited;
    private String message;

    public static OtpResult sent(String type) {
        return new OtpResult(true, false, type + " sent successfully. Check your phone.");
    }

    public static OtpResult rateLimited() {
        return new OtpResult(false, true, "Too many OTP requests. Please try again in 15 minutes.");
    }

    public static OtpResult failed(String errorMessage) {
        return new OtpResult(false, false, errorMessage);
    }
}