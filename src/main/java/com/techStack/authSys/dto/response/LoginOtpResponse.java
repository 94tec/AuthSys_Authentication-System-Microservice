package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

/**
 * Login OTP flow response.
 *
 * Returned after requesting a login OTP (2FA step).
 * Contains the temporary token needed for OTP verification.
 *
 * Being a record, accessors are plain method names (not getXxx/isXxx):
 *   rateLimited()      → not isRateLimited()
 *   temporaryToken()   → not getTemporaryToken()
 *   message()          → not getMessage()
 *
 * ⚠️ If you ever call this from a @Getter class context,
 *    use the record-style accessors above, NOT Lombok-style.
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

    /* =========================
       Static Factory Methods
       ========================= */

    /**
     * OTP sent successfully - user must verify OTP to continue.
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
     * Rate limit exceeded - user must wait before retrying.
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