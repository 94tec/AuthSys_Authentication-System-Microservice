package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * OTP Result DTO
 *
 * Enhanced with both getter styles for compatibility
 * Using class instead of record to avoid WebFlux/Reactive compilation issues.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtpResult {
    // ✅ Additional accessor methods for compatibility
    private boolean sent;
    private boolean rateLimited;
    private String message;

    // Static factory methods
    public static OtpResult sent(String type) {
        return OtpResult.builder()
                .sent(true)
                .rateLimited(false)
                .message(type + " sent successfully. Check your phone.")
                .build();
    }

    public static OtpResult rateLimited() {
        return OtpResult.builder()
                .sent(false)
                .rateLimited(true)
                .message("Too many OTP requests. Please try again in 15 minutes.")
                .build();
    }

    public static OtpResult failed(String errorMessage) {
        return OtpResult.builder()
                .sent(false)
                .rateLimited(false)
                .message(errorMessage)
                .build();
    }

}