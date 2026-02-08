package com.techStack.authSys.dto.internal;

import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import lombok.*;

import java.time.Instant;
import java.util.ArrayList;
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
    private List<Permissions> permissions;
    private boolean mfaRequired;
    private int loginAttempts;
    private Instant lastLogin;
    //private boolean forcePasswordChange;
    //private String message;

    // You can also define custom methods here if needed

}
