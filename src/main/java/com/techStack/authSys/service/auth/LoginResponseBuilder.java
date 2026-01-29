package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Builds authentication response objects.
 * Transforms AuthResult into client-facing AuthResponse DTOs.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginResponseBuilder {

    private final PermissionProvider permissionProvider;

    /**
     * Builds a successful login response with user info, tokens, and permissions.
     *
     * @param authResult Authentication result from the auth flow
     * @return ResponseEntity with AuthResponse
     */
    public ResponseEntity<AuthResponse> buildSuccessResponse(AuthResult authResult) {
        AuthResponse.UserInfo userInfo = buildUserInfo(authResult);
        List<Permissions> permissions = resolvePermissions(authResult);

        AuthResponse response = AuthResponse.builder()
                .accessToken(authResult.getAccessToken())
                .refreshToken(authResult.getRefreshToken())
                .accessTokenExpiry(authResult.getAccessTokenExpiry())
                .refreshTokenExpiry(authResult.getRefreshTokenExpiry())
                .user(userInfo)
                .permissions(permissions)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + response.getAccessToken())
                .body(response);
    }

    /**
     * Builds user info DTO from AuthResult.
     */
    private AuthResponse.UserInfo buildUserInfo(AuthResult authResult) {
        return AuthResponse.UserInfo.builder()
                .userId(authResult.getUser().getId())
                .email(authResult.getUser().getEmail())
                .firstName(authResult.getUser().getFirstName())
                .lastName(authResult.getUser().getLastName())
                .profileImageUrl(authResult.getUser().getProfilePictureUrl())
                .build();
    }

    /**
     * Resolves effective permissions for the user.
     */
    private List<Permissions> resolvePermissions(AuthResult authResult) {
        List<String> effectivePermissions = permissionProvider
                .resolveEffectivePermission(authResult.getUser())
                .stream()
                .toList();

        return permissionProvider.deserializePermissions(effectivePermissions);
    }
}
