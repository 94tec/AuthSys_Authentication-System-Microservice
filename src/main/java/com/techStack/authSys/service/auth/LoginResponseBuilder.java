package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Login Response Builder
 *
 * Builds authentication response objects.
 * Transforms AuthResult into client-facing AuthResponse DTOs.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginResponseBuilder {

    private final PermissionProvider permissionProvider;
    private final Clock clock;

    /* =========================
       Response Building
       ========================= */

    /**
     * Build successful login response with user info, tokens, and permissions
     */
    public ResponseEntity<AuthResponse> buildSuccessResponse(AuthResult authResult) {
        Instant now = clock.instant();

        log.debug("Building login response for user: {} at {}",
                authResult.getUser().getEmail(), now);

        AuthResponse.UserInfo userInfo = buildUserInfo(authResult);
        List<Permissions> permissions = resolvePermissions(authResult);

        AuthResponse response = AuthResponse.builder()
                .accessToken(authResult.getAccessToken())
                .refreshToken(authResult.getRefreshToken())
                .accessTokenExpiry(authResult.getAccessTokenExpiry())
                .refreshTokenExpiry(authResult.getRefreshTokenExpiry())
                .user(userInfo)
                .permissions(permissions)
                .timestamp(Date.from(now))
                .build();

        log.info("Login response built successfully for user: {} with {} permissions",
                authResult.getUser().getEmail(), permissions.size());

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + response.getAccessToken())
                .body(response);
    }

    /* =========================
       User Info Building
       ========================= */

    private AuthResponse.UserInfo buildUserInfo(AuthResult authResult) {
        return AuthResponse.UserInfo.builder()
                .userId(authResult.getUser().getId())
                .email(authResult.getUser().getEmail())
                .firstName(authResult.getUser().getFirstName())
                .lastName(authResult.getUser().getLastName())
                .profilePictureUrl(authResult.getUser().getProfilePictureUrl())
                .roles(authResult.getRoles() == null
                        ? Set.of()
                        : authResult.getRoles()
                        .stream()
                        .map(role -> role.name()) // Roles.ADMIN -> "ADMIN"
                        .collect(Collectors.toSet()))
                .mfaRequired(authResult.isMfaRequired())
                .build();
    }

    /* =========================
       Permission Resolution
       ========================= */

    /**
     * Resolve effective permissions for the user
     */
    private List<Permissions> resolvePermissions(AuthResult authResult) {
        List<String> effectivePermissions = permissionProvider
                .resolveEffectivePermission(authResult.getUser())
                .stream()
                .toList();

        log.debug("Resolved {} permissions for user: {}",
                effectivePermissions.size(), authResult.getUser().getEmail());

        return permissionProvider.deserializePermissions(effectivePermissions);
    }
}