package com.techStack.authSys.authorization.dto;

import com.techStack.authSys.authorization.models.Roles;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

/**
 * API response for a single RolePermissionOverride.
 * Returned by all read and write endpoints.
 */
@Data
@Builder
public class PermissionOverrideResponse {
    private Long    id;
    private Roles role;
    private String  permission;
    private Boolean granted;
    private String  setBy;
    private String  reason;
    private Instant createdAt;
    private Instant updatedAt;

    /** Human-readable: "GRANT" or "REVOKE" */
    public String getAction() {
        return Boolean.TRUE.equals(granted) ? "GRANT" : "REVOKE";
    }
}
