package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.techStack.authSys.models.user.User;
import lombok.*;

import java.util.List;
import java.util.Set;

/**
 * User Permissions DTO
 *
 * Used for authorization checks and permission verification.
 * Converts server-side roles and permissions into Strings for API responses.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserPermissionsDTO {

    private String userId;
    private List<String> roles;         // role names
    private List<String> permissions;   // user-specific additional permissions
    private Set<String> allPermissions; // combined role + additional + custom permissions

    /**
     * Create UserPermissionsDTO from User entity.
     *
     * Fix: user.getAllPermissions() already returns Set<String> — the old
     * .map(Permissions::name) was referencing a removed enum and is simply
     * deleted. No stream transformation is needed.
     */
    public static UserPermissionsDTO fromEntity(User user) {
        if (user == null) return null;

        return UserPermissionsDTO.builder()
                .userId(user.getId())
                .roles(user.getRoleNames() != null
                        ? user.getRoleNames()
                        : List.of())
                .permissions(user.getAdditionalPermissions() != null
                        ? user.getAdditionalPermissions()
                        : List.of())
                .allPermissions(user.getAllPermissions())
                .build();
    }

    /**
     * Check if the user has a specific permission.
     */
    public boolean hasPermission(String permission) {
        return allPermissions != null && allPermissions.contains(permission);
    }

    /**
     * Check if the user has a specific role.
     */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    /**
     * Check if the user has any of the specified roles.
     */
    public boolean hasAnyRole(String... roles) {
        if (this.roles == null || this.roles.isEmpty()) return false;
        for (String role : roles) {
            if (this.roles.contains(role)) return true;
        }
        return false;
    }
}