package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.techStack.authSys.models.user.User;
import lombok.*;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * User Permissions DTO
 *
 * Used for authorization checks and permission verification.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserPermissionsDTO {

    private String userId;
    private List<String> roles;
    private List<String> permissions;
    private Set<String> allPermissions;  // Combined role-based + additional permissions

    /**
     * Create UserPermissionsDTO from User entity.
     */
    public static UserPermissionsDTO fromEntity(User user) {
        if (user == null) {
            return null;
        }

        return UserPermissionsDTO.builder()
                .userId(user.getId())
                .roles(user.getRoleNames())
                .permissions(user.getAdditionalPermissions())
                .allPermissions(user.getAllPermissions())
                .build();
    }

    /**
     * Check if user has a specific permission.
     */
    public boolean hasPermission(String permission) {
        return allPermissions != null && allPermissions.contains(permission);
    }

    /**
     * Check if user has a specific role.
     */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    /**
     * Check if user has any of the specified roles.
     */
    public boolean hasAnyRole(String... roles) {
        if (this.roles == null) return false;
        for (String role : roles) {
            if (this.roles.contains(role)) {
                return true;
            }
        }
        return false;
    }
}