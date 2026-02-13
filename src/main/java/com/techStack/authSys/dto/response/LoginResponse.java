package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.techStack.authSys.models.user.User;
import lombok.Builder;

/**
 * Login Response DTO
 *
 * Supports multiple authentication flows:
 * - Normal login (full access)
 * - First-time login (password change required)
 * - Login with OTP (2FA)
 * - Rate limited
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginResponse(
        boolean success,
        boolean firstTimeLogin,
        boolean requiresOtp,
        boolean rateLimited,
        String temporaryToken,
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
        return LoginResponse.builder()
                .success(true)
                .firstTimeLogin(false)
                .requiresOtp(false)
                .rateLimited(false)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .user(user)
                .message(message)
                .build();
    }

    /**
     * First-time login - password change required
     */
    public static LoginResponse firstTimeLogin(
            String tempToken,
            String userId,
            String message) {
        return LoginResponse.builder()
                .success(true)
                .firstTimeLogin(true)
                .requiresOtp(false)
                .rateLimited(false)
                .temporaryToken(tempToken)
                .message(message)
                .build();
    }

    /**
     * Login OTP required (2FA)
     */
    public static LoginResponse loginOtpRequired(
            String tempToken,
            String userId,
            String message) {
        return LoginResponse.builder()
                .success(true)
                .firstTimeLogin(false)
                .requiresOtp(true)
                .rateLimited(false)
                .temporaryToken(tempToken)
                .message(message)
                .build();
    }

    /**
     * Rate limited
     */
    public static LoginResponse rateLimited(String message) {
        return LoginResponse.builder()
                .success(false)
                .firstTimeLogin(false)
                .requiresOtp(false)
                .rateLimited(true)
                .message(message)
                .build();
    }
}