package com.techStack.authSys.dto.response;

import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Represents the response returned after authentication attempts
 *
 * ✅ FIXED: success() method now properly sets success=true
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private boolean success;
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
        private Set<String> roles;
        private boolean mfaRequired;
        private String profilePictureUrl;

        @Builder.Default
        private Date timestamp = new Date();
    }

    /**
     * Helper method for successful authentication responses
     * ✅ FIXED: Now sets success=true
     */
    public static AuthResponse success(
            String accessToken,
            String refreshToken,
            Instant accessTokenExpiry,
            Instant refreshTokenExpiry,
            UserInfo user,
            List<Permissions> permissions) {

        return AuthResponse.builder()
                .success(true)  // ✅ FIXED: Added this line
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")  // ✅ Explicit setting
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
     * ✅ FIXED: Explicitly sets success=false
     */
    public static AuthResponse error(String warning) {
        return AuthResponse.builder()
                .success(false)  // ✅ FIXED: Added this line
                .warning(warning)
                .message("Authentication failed")
                .timestamp(new Date())
                .build();
    }

    /**
     * Helper method for warnings (e.g., email not verified)
     * ✅ FIXED: Explicitly sets success=false
     */
    public static AuthResponse warning(String warning, String message) {
        return AuthResponse.builder()
                .success(false)  // ✅ FIXED: Added this line
                .warning(warning)
                .message(message)
                .timestamp(new Date())
                .build();
    }

    /**
     * Helper for email not verified scenario
     * ✅ FIXED: Explicitly sets success=false
     */
    public static AuthResponse emailNotVerified(String warning) {
        return AuthResponse.builder()
                .success(false)  // ✅ FIXED: Added this line
                .warning(warning)
                .message("Email verification required")
                .timestamp(new Date())
                .build();
    }
}