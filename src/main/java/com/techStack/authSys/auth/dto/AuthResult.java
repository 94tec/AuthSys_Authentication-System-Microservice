package com.techStack.authSys.auth.dto;

import com.techStack.authSys.authorization.models.Roles;
import com.techStack.authSys.identity.models.User;
import lombok.*;

import java.time.Instant;
import java.util.List;

/**
 * ✅ Tracks result of authentication attempts including tokens, login attempts, etc.
 */
@Getter
@Setter
@Builder
@ToString
@AllArgsConstructor
public class AuthResult {
    private User user;
    private String userId;
    private String sessionId;
    private String accessToken;
    private String refreshToken;
    private Instant accessTokenExpiry;
    private Instant refreshTokenExpiry;
    private List<Roles> roles;
    private List<String> permissions;
    private boolean mfaRequired;
    private int loginAttempts;
    private Instant lastLogin;
    //private boolean forcePasswordChange;
    //private String message;

    // You can also define custom methods here if needed

}
