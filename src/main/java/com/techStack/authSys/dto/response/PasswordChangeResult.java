package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Password Change Result DTO
 *
 * Contains the result of a password change operation,
 * including whether OTP was sent successfully.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PasswordChangeResult(
        String message,
        boolean otpSent
) {

    /**
     * Create a successful password change result with OTP sent
     */
    public static PasswordChangeResult successWithOtp(String message) {
        return new PasswordChangeResult(message, true);
    }

    /**
     * Create a successful password change result but OTP failed
     */
    public static PasswordChangeResult successWithoutOtp(String message) {
        return new PasswordChangeResult(message, false);
    }

    /**
     * Create a failed password change result
     */
    public static PasswordChangeResult failure(String message) {
        return new PasswordChangeResult(message, false);
    }

    /**
     * Check if the operation was fully successful (password changed AND OTP sent)
     */
    public boolean isFullySuccessful() {
        return otpSent;
    }

    /**
     * Check if password was changed (regardless of OTP status)
     */
    public boolean passwordChanged() {
        return true; // If we have a result, password was changed
    }
}