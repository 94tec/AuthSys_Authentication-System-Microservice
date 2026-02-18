package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.techStack.authSys.models.user.User;

/**
 * Login Response DTO
 *
 * Supports multiple authentication flows:
 * - Normal login (full access)
 * - First-time login (password change required)
 * - Login with OTP (2FA)
 * - Rate limited
 *
 * ✅ FIXED: Removed @Builder (incompatible with records), added userId field
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginResponse(
        boolean success,
        boolean firstTimeLogin,
        boolean requiresOtp,
        boolean rateLimited,
        String temporaryToken,
        String userId,           // ✅ ADDED - was missing but used in factory methods
        String accessToken,
        String refreshToken,
        User user,
        String message
) {
    /**
     * Successful login with full access
     */
    public static LoginResponse success(
            String accessToken,
            String refreshToken,
            User user,
            String message) {
        return new LoginResponse(
                true,    // success
                false,   // firstTimeLogin
                false,   // requiresOtp
                false,   // rateLimited
                null,    // temporaryToken
                null,    // userId (full user object already provided)
                accessToken,
                refreshToken,
                user,
                message
        );
    }

    /**
     * First-time login - password change required
     */
    public static LoginResponse firstTimeLogin(
            String tempToken,
            String userId,
            String message) {
        return new LoginResponse(
                true,    // success
                true,    // firstTimeLogin
                false,   // requiresOtp
                false,   // rateLimited
                tempToken,
                userId,  // ✅ NOW ACTUALLY USED
                null,    // accessToken
                null,    // refreshToken
                null,    // user
                message
        );
    }

    /**
     * Login OTP required (2FA)
     */
    public static LoginResponse loginOtpRequired(
            String tempToken,
            String userId,
            String message) {
        return new LoginResponse(
                true,    // success
                false,   // firstTimeLogin
                true,    // requiresOtp
                false,   // rateLimited
                tempToken,
                userId,  // ✅ NOW ACTUALLY USED
                null,    // accessToken
                null,    // refreshToken
                null,    // user
                message
        );
    }

    /**
     * Rate limited
     */
    public static LoginResponse rateLimited(String message) {
        return new LoginResponse(
                false,   // success
                false,   // firstTimeLogin
                false,   // requiresOtp
                true,    // rateLimited
                null,    // temporaryToken
                null,    // userId
                null,    // accessToken
                null,    // refreshToken
                null,    // user
                message
        );
    }
}