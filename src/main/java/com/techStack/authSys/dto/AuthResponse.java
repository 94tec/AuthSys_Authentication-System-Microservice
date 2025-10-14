package com.techStack.authSys.dto;

import com.google.cloud.Timestamp;
import com.techStack.authSys.models.Permissions;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Represents the response returned after successful authentication
 */
@Data
@Builder
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
    private Instant accessTokenExpiry;
    private Instant refreshTokenExpiry;
    private UserInfo user;
    private List<Permissions> permissions;
    private Date timestamp;
    private String warning; // For password expiry warnings

    public AuthResponse() {

    }

    @Data
    @Builder
    public static class UserInfo {
        private String userId;
        private String email;
        private String firstName;
        private String lastName;
        private Date timestamp;
        private boolean MfaRequired;
        private String profileImageUrl;
    }

    // Builder pattern for easy construction
    public static AuthResponseBuilder builder() {
        return new AuthResponseBuilder();
    }

    public static class AuthResponseBuilder {
        private final AuthResponse response = new AuthResponse();

        public AuthResponseBuilder accessToken(String accessToken) {
            response.setAccessToken(accessToken);
            return this;
        }

        public AuthResponseBuilder refreshToken(String refreshToken) {
            response.setRefreshToken(refreshToken);
            return this;
        }

        public AuthResponseBuilder accessTokenExpiry(Instant expiry) {
            response.setAccessTokenExpiry(expiry);
            return this;
        }

        public AuthResponseBuilder refreshTokenExpiry(Instant expiry) {
            response.setRefreshTokenExpiry(expiry);
            return this;
        }

        public AuthResponseBuilder user(UserInfo user) {
            response.setUser(user);
            return this;
        }

        public AuthResponseBuilder permissions(List<Permissions> permissions) {
            response.setPermissions(permissions);
            return this;
        }

        public AuthResponseBuilder warning(String warning) {
            response.setWarning(warning);
            return this;
        }
        public AuthResponseBuilder timestamp(Date date) {
            response.setTimestamp(date);
            return this;
        }
        public AuthResponse build() {
            return response;
        }


    }
}
