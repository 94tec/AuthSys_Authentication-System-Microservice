package com.techStack.authSys.authorization.dto;

import com.techStack.authSys.authorization.models.Roles;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Request to create or update a permission override.
 * POST/PUT /api/admin/system/role-permissions
 *
 * Maps directly to RoleAccessManagementService.setPermissionOverride() params.
 *
 * The reason field is mandatory — every permission change must be documented.
 */
public record PermissionOverrideRequest(

        @NotNull(message = "Role is required")
        Roles role,

        @NotBlank(message = "Permission is required")
        @Size(max = 150, message = "Permission string must be under 150 characters")
        String permission,

        @NotNull(message = "Granted flag is required — true = grant, false = revoke")
        Boolean granted,

        @NotBlank(message = "Reason is required for every permission change")
        @Size(max = 500, message = "Reason must be under 500 characters")
        String reason

) {}
