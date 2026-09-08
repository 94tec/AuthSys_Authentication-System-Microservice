package com.techStack.authSys.authorization.dto;

import com.techStack.authSys.authorization.models.Roles;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Set;

/**
 * Full permission view for a role — base defaults + active overrides.
 *
 * GET /api/admin/system/role-permissions/{role}/effective
 *
 * Used by the SUPER_ADMIN UI to show:
 *   - What permissions a role currently has (effective set after overrides)
 *   - Which ones come from the default PermissionProvider
 *   - Which ones have been custom-added or removed via overrides
 */
@Data
@Builder
public class RolePermissionSummary {
    private Roles role;
    private String roleDisplayName;

    /** Resolved effective permission set (base + grants - revocations). */
    private Set<String> effectivePermissions;

    /** Permissions from PermissionProvider defaults only. */
    private Set<String> defaultPermissions;

    /** Permissions that have been explicitly granted on top of defaults. */
    private Set<String> grantedOverrides;

    /** Permissions that have been explicitly revoked from defaults. */
    private Set<String> revokedOverrides;

    /** Count summary */
    private int totalEffective;
    private int totalGranted;
    private int totalRevoked;

    /** Active override rows for this role */
    private List<PermissionOverrideResponse> overrides;
}
