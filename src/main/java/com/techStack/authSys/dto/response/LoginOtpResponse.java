package com.techStack.authSys.dto.response;


import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

/**
 * Login OTP Response DTO
 *
 * Response after requesting login OTP.
 * Contains temporary token for OTP verification.
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginOtpResponse(
        boolean success,
        boolean otpRequired,
        boolean rateLimited,
        String temporaryToken,
        String userId,
        String message
) {
    /**
     * OTP sent successfully
     */
    public static LoginOtpResponse otpSent(String tempToken, String userId, String message) {
        return LoginOtpResponse.builder()
                .success(true)
                .otpRequired(true)
                .rateLimited(false)
                .temporaryToken(tempToken)
                .userId(userId)
                .message(message)
                .build();
    }

    /**
     * Rate limited
     */
    public static LoginOtpResponse rateLimited(String message) {
        return LoginOtpResponse.builder()
                .success(false)
                .otpRequired(false)
                .rateLimited(true)
                .temporaryToken(null)
                .userId(null)
                .message(message)
                .build();
    }
}
