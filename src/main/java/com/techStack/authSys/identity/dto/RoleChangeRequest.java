package com.techStack.authSys.identity.dto;

import com.techStack.authSys.authorization.models.Roles;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Request to change a user's role.
 * POST /api/admin/system/users/{userId}/role
 *
 * Maps to RoleAccessManagementService.changeUserRole() parameters.
 * The reason is not in the service signature but logged at the controller
 * for the audit trail before delegating to the service.
 */
public record RoleChangeRequest(

        @NotNull(message = "New role is required")
        Roles newRole,

        @NotBlank(message = "Reason is required for every role change")
        @Size(max = 500)
        String reason

) {}
