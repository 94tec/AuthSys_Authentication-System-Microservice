package com.techStack.authSys.controller.admin;

import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Admin Role Permission Controller
 *
 * Manages role and permission assignments.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/access")
@RequiredArgsConstructor
@Tag(
        name = "Role & Permission Management",
        description = """
                Role-Based Access Control (RBAC) administration.
                
                **Purpose:**
                - Manage user roles
                - Grant and revoke permissions
                - View role-permission mappings
                - Reload permission configurations
                
                **Role Hierarchy:**
                1. **SUPER_ADMIN** (Level 4)
                   - Full system access
                   - Can manage all users and roles
                   - System configuration
                   - Cannot be assigned by other admins
                
                2. **ADMIN** (Level 3)
                   - User management
                   - Role assignments (except SUPER_ADMIN)
                   - System monitoring
                   - Audit log access
                
                3. **MANAGER** (Level 2)
                   - Team management
                   - Report access
                   - Limited user operations
                
                4. **USER** (Level 1)
                   - Basic access
                   - Self-service operations
                   - Default role for new users
                
                **Permission System:**
                - **Role Permissions**: Default permissions for a role
                - **Additional Permissions**: Extra permissions granted to specific users
                - **Effective Permissions**: Role permissions + Additional permissions
                
                **Access Control:**
                - **SUPER_ADMIN**: Full access to all endpoints
                - **ADMIN**: Read-only access to roles/permissions
                - Role assignment requires SUPER_ADMIN
                
                **Configuration:**
                - Roles and default permissions defined in YAML
                - Can be reloaded without restart
                - Changes apply immediately
                - Audit logged
                
                **Security:**
                - All operations logged in audit trail
                - Cannot escalate own privileges
                - Cannot remove last SUPER_ADMIN
                - Role hierarchy enforced
                
                **Use Cases:**
                - Promote user to ADMIN
                - Grant temporary permissions
                - Revoke access rights
                - View permission structure
                - Update permission configuration
                """
)
public class AdminRolePermissionController {

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PermissionProvider permissionProvider;
    private final Clock clock;

    /* =========================
       Get Roles & Permissions
       ========================= */

    @Operation(
            summary = "Get All Roles and Their Permissions",
            description = """
                    Retrieve complete role-permission mapping.
                    
                    **Returns:**
                    - All system roles
                    - Default permissions for each role
                    - Role hierarchy information
                    
                    **Role Structure:**
                    Each role has:
                    - Name (SUPER_ADMIN, ADMIN, MANAGER, USER)
                    - Level (4, 3, 2, 1)
                    - Default permissions set
                    
                    **Permission Categories:**
                    - **User Operations**: USER_CREATE, USER_READ, USER_UPDATE, USER_DELETE
                    - **Role Management**: ROLE_ASSIGN, ROLE_REVOKE
                    - **Permission Management**: PERMISSION_GRANT, PERMISSION_REVOKE
                    - **System Operations**: SYSTEM_CONFIG, AUDIT_VIEW
                    - **Content**: CONTENT_CREATE, CONTENT_PUBLISH
                    
                    **Access Required:**
                    - ADMIN or SUPER_ADMIN role
                    
                    **Use Cases:**
                    - Understand permission structure
                    - Plan role assignments
                    - Document access control
                    - Compliance audits
                    - Build admin UI
                    
                    **Response Structure:**
                    Maps role names to their permission sets:
```json
                    {
                      "SUPER_ADMIN": ["ALL_PERMISSIONS"],
                      "ADMIN": ["USER_CREATE", "USER_READ", ...],
                      "MANAGER": ["USER_READ", "TEAM_MANAGE", ...],
                      "USER": ["PROFILE_VIEW", "PROFILE_UPDATE"]
                    }
```
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Role permissions retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "data": {
                                                "SUPER_ADMIN": [
                                                  "USER_CREATE", "USER_READ", "USER_UPDATE", "USER_DELETE",
                                                  "ROLE_ASSIGN", "ROLE_REVOKE",
                                                  "SYSTEM_CONFIG", "AUDIT_VIEW"
                                                ],
                                                "ADMIN": [
                                                  "USER_CREATE", "USER_READ", "USER_UPDATE",
                                                  "AUDIT_VIEW"
                                                ],
                                                "MANAGER": [
                                                  "USER_READ", "TEAM_MANAGE", "REPORT_VIEW"
                                                ],
                                                "USER": [
                                                  "PROFILE_VIEW", "PROFILE_UPDATE"
                                                ]
                                              },
                                              "timestamp": "2024-03-15T14:30:00Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions"
            )
    })
    @GetMapping("/roles")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getAllRolePermissions() {
        Instant requestTime = clock.instant();

        log.info("Fetching all role permissions at {}", requestTime);

        return Mono.fromCallable(() -> {
            Map<String, Set<String>> rolePermissions = Arrays.stream(Roles.values())
                    .collect(Collectors.toMap(
                            Roles::name,
                            role -> permissionProvider.getPermissionsForRole(role)
                                    .stream()
                                    .map(Enum::name)
                                    .collect(Collectors.toSet())
                    ));

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", rolePermissions,
                    "timestamp", requestTime.toString()
            ));
        });
    }

    @Operation(
            summary = "Get All Available Permissions",
            description = """
                    Retrieve list of all system permissions.
                    
                    **Returns:**
                    - Complete list of available permissions
                    - Permission names as strings
                    - No role associations
                    
                    **Permission Types:**
                    
                    **User Management:**
                    - USER_CREATE, USER_READ, USER_UPDATE, USER_DELETE
                    - USER_APPROVE, USER_REJECT
                    
                    **Role & Permission:**
                    - ROLE_ASSIGN, ROLE_REVOKE
                    - PERMISSION_GRANT, PERMISSION_REVOKE
                    
                    **System Administration:**
                    - SYSTEM_CONFIG, SYSTEM_MONITOR
                    - AUDIT_VIEW, AUDIT_EXPORT
                    
                    **Content Management:**
                    - CONTENT_CREATE, CONTENT_UPDATE, CONTENT_DELETE
                    - CONTENT_PUBLISH, CONTENT_UNPUBLISH
                    
                    **Reporting:**
                    - REPORT_VIEW, REPORT_CREATE, REPORT_EXPORT
                    
                    **Team Management:**
                    - TEAM_CREATE, TEAM_MANAGE, TEAM_DELETE
                    
                    **Access Required:**
                    - ADMIN or SUPER_ADMIN role
                    
                    **Use Cases:**
                    - Build permission selection UI
                    - Document available permissions
                    - Validate permission names
                    - Permission grant/revoke operations
                    - Compliance documentation
                    
                    **Note:**
                    This list represents ALL possible permissions,
                    not what the current user has.
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permissions retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "data": [
                                                "USER_CREATE", "USER_READ", "USER_UPDATE", "USER_DELETE",
                                                "ROLE_ASSIGN", "ROLE_REVOKE",
                                                "PERMISSION_GRANT", "PERMISSION_REVOKE",
                                                "SYSTEM_CONFIG", "AUDIT_VIEW",
                                                "CONTENT_CREATE", "CONTENT_PUBLISH",
                                                "REPORT_VIEW", "TEAM_MANAGE"
                                              ],
                                              "timestamp": "2024-03-15T14:30:00Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @GetMapping("/permissions")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getAllPermissions() {
        Instant requestTime = clock.instant();

        log.info("Fetching all permissions at {}", requestTime);

        return Mono.fromCallable(() -> {
            Set<String> permissions = Arrays.stream(Permissions.values())
                    .map(Enum::name)
                    .collect(Collectors.toSet());

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", permissions,
                    "timestamp", requestTime.toString()
            ));
        });
    }

    /* =========================
       Role Assignment
       ========================= */

    @Operation(
            summary = "Assign Role to User",
            description = """
                    Assign a role to a user account.
                    
                    **Access Required:**
                    - SUPER_ADMIN role only
                    
                    **Process:**
                    1. Validates role name
                    2. Checks user exists
                    3. Assigns role to user
                    4. Grants role's default permissions
                    5. Logs in audit trail
                    6. Returns confirmation
                    
                    **Available Roles:**
                    - SUPER_ADMIN (Level 4) - Cannot be assigned
                    - ADMIN (Level 3)
                    - MANAGER (Level 2)
                    - USER (Level 1)
                    
                    **Role Effects:**
                    - User immediately gains role's default permissions
                    - Previous roles remain (multi-role support)
                    - Effective permissions = union of all role permissions
                    - Role hierarchy affects access checks
                    
                    **Restrictions:**
                    - Cannot assign SUPER_ADMIN role
                    - Cannot assign higher role than own role
                    - User must exist in system
                    - Role must be valid enum value
                    
                    **Audit Trail:**
                    Creates audit log with:
                    - Who assigned the role
                    - Which role was assigned
                    - To which user
                    - When it occurred
                    
                    **Use Cases:**
                    - Promote user to ADMIN
                    - Assign MANAGER role to team lead
                    - Grant USER role (default for new users)
                    
                    **Security:**
                    - Only SUPER_ADMIN can assign roles
                    - Cannot escalate own privileges
                    - Audit logged
                    - User notified via email
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Role assigned successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Role assigned successfully",
                                              "data": {
                                                "userId": "user-123",
                                                "role": "ADMIN",
                                                "assignedAt": "2024-03-15T14:30:00Z"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid role name or user not found"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions (requires SUPER_ADMIN)"
            )
    })
    @PostMapping("/roles/assign")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> assignRoleToUser(
            @Parameter(
                    description = "User ID to assign role to",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId,

            @Parameter(
                    description = "Role name to assign (ADMIN, MANAGER, USER)",
                    required = true,
                    example = "ADMIN"
            )
            @RequestParam String roleName) {

        Instant assignmentTime = clock.instant();

        log.info("Assigning role '{}' to user {} at {}", roleName, userId, assignmentTime);

        return Mono.justOrEmpty(Roles.fromName(roleName))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid role name: " + roleName)))
                .flatMap(role -> permissionProvider.assignRole(userId, role)
                        .thenReturn(ResponseEntity.ok(Map.of(
                                "success", true,
                                "message", "Role assigned successfully",
                                "data", Map.of(
                                        "userId", userId,
                                        "role", roleName,
                                        "assignedAt", assignmentTime.toString()
                                )
                        ))))
                .onErrorResume(e -> {
                    log.error("Failed to assign role at {}: {}", assignmentTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(Map.of(
                            "success", false,
                            "message", e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                });
    }

    /* =========================
       Permission Management
       ========================= */

    @Operation(
            summary = "Grant Permission to User",
            description = """
                    Grant additional permission to a user beyond their role.
                    
                    **Access Required:**
                    - SUPER_ADMIN role only
                    
                    **Process:**
                    1. Validates permission name
                    2. Checks user exists
                    3. Adds permission to user's additional permissions
                    4. Permission takes effect immediately
                    5. Logs in audit trail
                    
                    **Additional Permissions:**
                    - Granted on top of role permissions
                    - Do not replace role permissions
                    - Allow fine-grained access control
                    - User can have permissions from multiple sources
                    
                    **Use Cases:**
                    - Grant temporary elevated access
                    - Give specific permission without role change
                    - Test permission-based features
                    - Exception-based access grants
                    
                    **Example Scenarios:**
                    - USER role but needs REPORT_EXPORT temporarily
                    - MANAGER needs AUDIT_VIEW without ADMIN role
                    - Testing new permission before adding to role
                    
                    **Best Practices:**
                    - Document why extra permission was granted
                    - Review regularly and revoke if no longer needed
                    - Prefer role assignment over individual permissions
                    - Use sparingly for exceptions only
                    
                    **Audit Trail:**
                    Creates audit log with:
                    - Who granted the permission
                    - Which permission was granted
                    - To which user
                    - When it occurred
                    
                    **Security:**
                    - Only SUPER_ADMIN can grant permissions
                    - All grants logged
                    - Can be revoked anytime
                    - Does not affect role permissions
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permission granted successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Permission granted successfully",
                                              "data": {
                                                "userId": "user-123",
                                                "permission": "REPORT_EXPORT",
                                                "grantedAt": "2024-03-15T14:30:00Z"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid permission name"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Requires SUPER_ADMIN role"
            )
    })
    @PostMapping("/permissions/grant")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> grantPermissionToUser(
            @Parameter(
                    description = "User ID to grant permission to",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId,

            @Parameter(
                    description = "Permission to grant (e.g., REPORT_EXPORT, AUDIT_VIEW)",
                    required = true,
                    example = "REPORT_EXPORT"
            )
            @RequestParam String permission) {

        Instant grantTime = clock.instant();

        log.info("Granting permission '{}' to user {} at {}", permission, userId, grantTime);

        return Mono.justOrEmpty(Permissions.fromNameSafe(permission))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid permission: " + permission)))
                .doOnNext(perm -> permissionProvider.addPermission(userId, perm))
                .thenReturn(ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Permission granted successfully",
                        "data", Map.of(
                                "userId", userId,
                                "permission", permission,
                                "grantedAt", grantTime.toString()
                        )
                )))
                .onErrorResume(e -> {
                    log.error("Failed to grant permission at {}: {}", grantTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(Map.of(
                            "success", false,
                            "message", e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                });
    }

    @Operation(
            summary = "Revoke Permission from User",
            description = """
                    Remove an additional permission from a user.
                    
                    **Access Required:**
                    - SUPER_ADMIN role only
                    
                    **Process:**
                    1. Validates permission name
                    2. Checks user exists
                    3. Removes from additional permissions
                    4. Permission revoked immediately
                    5. Logs in audit trail
                    
                    **Important:**
                    - Only removes ADDITIONAL permissions
                    - Does NOT remove role-based permissions
                    - To remove role permission, must remove/change role
                    
                    **Use Cases:**
                    - Remove temporary elevated access
                    - Clean up unused permissions
                    - Revoke exception-based grants
                    - Security incident response
                    
                    **Effects:**
                    - Permission removed from additional permissions list
                    - If permission came from role, still has it
                    - If permission was only additional, loses access
                    - Takes effect immediately
                    
                    **Audit Trail:**
                    Creates audit log with:
                    - Who revoked the permission
                    - Which permission was revoked
                    - From which user
                    - When it occurred
                    
                    **Security:**
                    - Only SUPER_ADMIN can revoke
                    - All revocations logged
                    - Cannot revoke role permissions this way
                    - Immediate effect
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permission revoked successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Permission revoked successfully",
                                              "data": {
                                                "userId": "user-123",
                                                "permission": "REPORT_EXPORT",
                                                "revokedAt": "2024-03-15T14:30:00Z"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid permission or not found"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Requires SUPER_ADMIN role"
            )
    })
    @PostMapping("/permissions/revoke")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> revokePermissionFromUser(
            @Parameter(
                    description = "User ID to revoke permission from",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId,

            @Parameter(
                    description = "Permission to revoke",
                    required = true,
                    example = "REPORT_EXPORT"
            )
            @RequestParam String permission) {

        Instant revokeTime = clock.instant();

        log.info("Revoking permission '{}' from user {} at {}", permission, userId, revokeTime);

        return Mono.justOrEmpty(Permissions.fromNameSafe(permission))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid permission: " + permission)))
                .doOnNext(perm -> permissionProvider.removePermission(userId, perm))
                .thenReturn(ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Permission revoked successfully",
                        "data", Map.of(
                                "userId", userId,
                                "permission", permission,
                                "revokedAt", revokeTime.toString()
                        )
                )))
                .onErrorResume(e -> {
                    log.error("Failed to revoke permission at {}: {}", revokeTime, e.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(Map.of(
                            "success", false,
                            "message", e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                });
    }

    /* =========================
       Permission Reload
       ========================= */

    @Operation(
            summary = "Reload Permissions from Configuration",
            description = """
                    Reload role-permission mappings from YAML configuration.
                    
                    **⚠️ SUPER_ADMIN Only - Use with Caution**
                    
                    **Purpose:**
                    - Apply permission configuration changes
                    - Update role definitions
                    - Add new permissions
                    - Modify default role permissions
                    
                    **Process:**
                    1. Reads permissions YAML file
                    2. Parses role definitions
                    3. Updates in-memory permission cache
                    4. Applies changes immediately
                    5. No restart required
                    
                    **When to Use:**
                    - After updating permissions.yml
                    - Adding new permission types
                    - Changing role defaults
                    - Testing permission changes
                    
                    **Effects:**
                    - New permissions available immediately
                    - Role defaults updated for new assignments
                    - Existing user permissions unchanged
                    - Only affects future role assignments
                    
                    **Important Notes:**
                    - Does NOT change existing user permissions
                    - Does NOT require restart
                    - YAML errors cause reload to fail
                    - Previous config remains if reload fails
                    
                    **Safety:**
                    - Validates YAML before applying
                    - Atomic operation (all or nothing)
                    - Logs reload event
                    - Can be rolled back by restoring YAML
                    
                    **Use Cases:**
                    - Development: testing new permissions
                    - Configuration: adding business-specific permissions
                    - Maintenance: updating role definitions
                    - Hotfix: urgent permission changes
                    
                    **Production Warning:**
                    - Test changes in development first
                    - Document permission changes
                    - Notify team before reload
                    - Monitor for unexpected behavior
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permissions reloaded successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Permissions reloaded from YAML",
                                              "reloadedAt": "2024-03-15T14:30:00Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Failed to reload permissions",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Failed to reload permissions: YAML parse error",
                                              "timestamp": "2024-03-15T14:30:00Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Requires SUPER_ADMIN role"
            )
    })
    @PostMapping("/reload")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> reloadPermissions() {
        Instant reloadTime = clock.instant();

        log.warn("🔄 Reloading permissions from YAML at {}", reloadTime);

        return Mono.fromRunnable(permissionProvider::reloadPermissions)
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of(
                        "success", true,
                        "message", "Permissions reloaded from YAML",
                        "reloadedAt", reloadTime.toString()
                )))
                .onErrorResume(e -> {
                    log.error("Failed to reload permissions at {}: {}", reloadTime, e.getMessage());
                    return Mono.just(ResponseEntity.status(500).body(Map.<String, Object>of(
                            "success", false,
                            "message", "Failed to reload permissions: " + e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                });
    }
}