package com.techStack.authSys.identity.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Response shape for GET /api/auth/me.
 *
 * Deliberately a SUPERSET of what either frontend's User type currently
 * declares, rather than picking one shape — the two frontends disagree
 * with each other:
 *
 *   damuchi-ops-frontend types/idx.ts User:
 *     displayName, permissions, status: "ACTIVE"|"PENDING_APPROVAL"|"DISABLED"
 *
 *   authsys-frontend types/auth.ts User/UserProfile:
 *     firstName + lastName (no displayName), no permissions field,
 *     status: "ACTIVE"|"PENDING_APPROVAL"|"REJECTED"|"LOCKED"|"DISABLED"
 *
 * Sending both firstName/lastName AND a derived displayName, plus
 * permissions and status, means neither frontend's current field reads
 * break — but the two frontend User types should eventually be reconciled
 * into one shared shape (matches the earlier "extract a shared package"
 * recommendation) rather than silently diverging further. Not done here —
 * that's a frontend-side decision about which shape is canonical, not
 * something this backend DTO should force.
 */
@Data
@Builder
public class CurrentUserResponse {
    private String id;
    private String email;
    private String firstName;
    private String lastName;
    private String displayName;   // derived: firstName + " " + lastName
    private String status;        // User.getStatus().name() — see note in PATCH_AuthController_me_endpoint_v2.md on the status-set gap
    private List<String> roles;
    private List<String> permissions;
}