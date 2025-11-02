package com.techStack.authSys.dto;

import com.techStack.authSys.models.Permissions;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Represents the response returned after authentication attempts
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String accessToken;
    private String refreshToken;

    @Builder.Default
    private String tokenType = "Bearer";

    private Instant accessTokenExpiry;
    private Instant refreshTokenExpiry;
    private UserInfo user;
    private List<Permissions> permissions;

    @Builder.Default
    private Date timestamp = new Date();

    private String warning; // For errors, password expiry warnings, etc.
    private String message; // Optional success/info message

    /**
     * Nested UserInfo class for user details
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserInfo {
        private String userId;
        private String email;
        private String firstName;
        private String lastName;
        private boolean mfaRequired;
        private String profileImageUrl;

        @Builder.Default
        private Date timestamp = new Date();
    }

    /**
     * Helper method for successful authentication responses
     */
    public static AuthResponse success(String accessToken, String refreshToken,
                                       Instant accessTokenExpiry, Instant refreshTokenExpiry,
                                       UserInfo user, List<Permissions> permissions) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpiry(accessTokenExpiry)
                .refreshTokenExpiry(refreshTokenExpiry)
                .user(user)
                .permissions(permissions)
                .message("Authentication successful")
                .timestamp(new Date())
                .build();
    }

    /**
     * Helper method for authentication errors
     */
    public static AuthResponse error(String warning) {
        return AuthResponse.builder()
                .warning(warning)
                .message("Authentication failed")
                .timestamp(new Date())
                .build();
    }

    /**
     * Helper method for warnings (e.g., email not verified)
     */
    public static AuthResponse warning(String warning, String message) {
        return AuthResponse.builder()
                .warning(warning)
                .message(message)
                .timestamp(new Date())
                .build();
    }

    /**
     * Helper for email not verified scenario
     */
    public static AuthResponse emailNotVerified(String warning) {
        return AuthResponse.builder()
                .warning(warning)
                .message("Email verification required")
                .timestamp(new Date())
                .build();
    }
}