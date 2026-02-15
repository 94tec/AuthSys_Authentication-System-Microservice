package com.techStack.authSys.controller.audit;

import com.techStack.authSys.dto.response.AuditLogDTO;
import com.techStack.authSys.dto.response.UserPermissionsDTO;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.audit.AuditEventLog;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.observability.AuditLogService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
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
import java.util.List;
import java.util.Map;

/**
 * Audit Log Controller
 *
 * Provides access to audit logs and permission checks.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/audit-logs")
@RequiredArgsConstructor
@Tag(
        name = "Audit Logs",
        description = """
                Audit logging and permission tracking.
                
                **Purpose:**
                - Track all system operations
                - Monitor user actions
                - Maintain compliance records
                - Security investigation
                - Permission auditing
                
                **What Gets Logged:**
                - User authentication (login, logout, failures)
                - Account changes (creation, updates, deletion)
                - Role assignments and revocations
                - Permission grants and removals
                - Password changes and resets
                - Security events (locks, unlocks)
                - Admin operations
                - Permission checks
                
                **Log Retention:**
                - Stored in Firestore
                - Indexed by user, action type, timestamp
                - Permanent storage (no auto-deletion)
                - Searchable and filterable
                
                **Access Control:**
                - **ADMIN role**: Full access to all logs
                - **Users**: Access only to their own logs
                - Permission checks logged with admin identity
                
                **Compliance:**
                - Supports SOC 2, ISO 27001, GDPR requirements
                - Immutable audit trail
                - Includes who, what, when, where
                - Tracks all privilege escalations
                
                **Use Cases:**
                - Security incident investigation
                - Compliance audits
                - User activity monitoring
                - Access pattern analysis
                - Troubleshooting user issues
                - Regulatory reporting
                """
)
public class AuditLogController {

    /* =========================
       Dependencies
       ========================= */

    private final AuditLogService auditLogService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PermissionProvider permissionProvider;
    private final Clock clock;

    /* =========================
       Audit Log Retrieval
       ========================= */

    @Operation(
            summary = "Get All Audit Logs",
            description = """
                    Retrieve all audit logs across the system.
                    
                    **Access Required:**
                    - ADMIN role
                    
                    **Returns:**
                    - All audit events from all users
                    - Sorted by timestamp (newest first)
                    - Includes metadata for each event
                    - Full action details
                    
                    **Log Structure:**
                    Each log entry contains:
                    - **ID**: Unique log identifier
                    - **Action**: Type of action (LOGIN, PASSWORD_CHANGE, etc.)
                    - **User**: Who performed the action
                    - **Target**: Who/what was affected
                    - **Timestamp**: When it occurred
                    - **IP Address**: Where it came from
                    - **Result**: Success or failure
                    - **Metadata**: Additional context
                    
                    **Common Actions:**
                    - LOGIN, LOGOUT, LOGIN_FAILED
                    - PASSWORD_CHANGE, PASSWORD_RESET
                    - USER_CREATED, USER_UPDATED, USER_DELETED
                    - ROLE_ASSIGNED, ROLE_REVOKED
                    - PERMISSION_GRANTED, PERMISSION_REVOKED
                    - ACCOUNT_LOCKED, ACCOUNT_UNLOCKED
                    - PERMISSION_CHECK
                    
                    **Filtering:**
                    Use other endpoints to filter by:
                    - Specific user: GET /user/{userId}
                    - Action type: GET /action/{actionType}
                    
                    **Performance:**
                    - Large result sets may be paginated
                    - Consider filtering for better performance
                    - Response time depends on total log count
                    
                    **Use Cases:**
                    - System-wide security review
                    - Compliance audits
                    - Pattern analysis
                    - Anomaly detection
                    - Generate compliance reports
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Audit logs retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "data": [
                                                {
                                                  "id": "log-123",
                                                  "action": "LOGIN",
                                                  "userId": "user-456",
                                                  "targetUser": null,
                                                  "timestamp": "2024-03-15T14:22:30Z",
                                                  "ipAddress": "192.168.1.100",
                                                  "userAgent": "Mozilla/5.0...",
                                                  "success": true,
                                                  "metadata": {
                                                    "loginMethod": "PASSWORD",
                                                    "deviceFingerprint": "abc123..."
                                                  }
                                                },
                                                {
                                                  "id": "log-124",
                                                  "action": "PASSWORD_CHANGE",
                                                  "userId": "user-456",
                                                  "timestamp": "2024-03-15T14:20:00Z",
                                                  "success": true,
                                                  "metadata": {
                                                    "reason": "USER_INITIATED"
                                                  }
                                                }
                                              ],
                                              "count": 2,
                                              "timestamp": "2024-03-15T14:30:00Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions (requires ADMIN role)"
            )
    })
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAuditLogs() {
        Instant requestTime = clock.instant();

        log.info("Fetching all audit logs at {}", requestTime);

        List<AuditLogDTO> logs = auditLogService.getAuditLogs();

        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", logs,
                "count", logs.size(),
                "timestamp", requestTime.toString()
        ));
    }

    @Operation(
            summary = "Get Audit Logs by User",
            description = """
                    Retrieve audit logs for a specific user.
                    
                    **Access Control:**
                    - **ADMIN**: Can view any user's logs
                    - **User**: Can only view their own logs
                    
                    **Returns:**
                    - All actions performed by the user
                    - All actions performed on the user (by others)
                    - Sorted by timestamp (newest first)
                    - Includes success and failed actions
                    
                    **Typical User Actions:**
                    - Login attempts (successful and failed)
                    - Password changes
                    - Profile updates
                    - Permission requests
                    - Resource access
                    
                    **Actions on User:**
                    - Role assignments by admin
                    - Account locks/unlocks
                    - Password resets initiated by admin
                    - Permission grants/revocations
                    - Account modifications
                    
                    **Use Cases:**
                    - User activity review
                    - Investigate suspicious behavior
                    - User support (troubleshooting)
                    - Verify user's claims
                    - Track privilege changes
                    
                    **Self-Service:**
                    Users can view their own audit logs to:
                    - Verify their recent activity
                    - Check for unauthorized access
                    - See when permissions changed
                    - Review login history
                    
                    **Privacy:**
                    - Users cannot see other users' logs
                    - Sensitive data may be redacted
                    - Admin actions clearly attributed
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "User audit logs retrieved",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "data": [
                                                {
                                                  "id": "log-456",
                                                  "action": "LOGIN",
                                                  "userId": "user-123",
                                                  "timestamp": "2024-03-15T14:22:30Z",
                                                  "ipAddress": "192.168.1.100",
                                                  "success": true
                                                },
                                                {
                                                  "id": "log-457",
                                                  "action": "ROLE_ASSIGNED",
                                                  "performedBy": "admin-789",
                                                  "targetUser": "user-123",
                                                  "timestamp": "2024-03-15T10:00:00Z",
                                                  "metadata": {
                                                    "role": "MANAGER",
                                                    "reason": "Promotion"
                                                  }
                                                }
                                              ],
                                              "userId": "user-123",
                                              "count": 2,
                                              "timestamp": "2024-03-15T14:30:00Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Cannot access another user's logs"
            )
    })
    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.uid")
    public ResponseEntity<Map<String, Object>> getAuditLogsByUser(
            @Parameter(
                    description = "User ID to get audit logs for",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId) {

        Instant requestTime = clock.instant();

        log.info("Fetching audit logs for user {} at {}", userId, requestTime);

        List<AuditLogDTO> logs = auditLogService.getAuditLogsByUser(userId);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", logs,
                "userId", userId,
                "count", logs.size(),
                "timestamp", requestTime.toString()
        ));
    }

    @Operation(
            summary = "Get Audit Logs by Action Type",
            description = """
                    Retrieve all audit logs for a specific action type.
                    
                    **Access Required:**
                    - ADMIN role
                    
                    **Action Types:**
                    
                    **Authentication:**
                    - LOGIN, LOGOUT, LOGIN_FAILED
                    - TOKEN_REFRESH, SESSION_EXPIRED
                    
                    **Account Management:**
                    - USER_CREATED, USER_UPDATED, USER_DELETED
                    - USER_APPROVED, USER_REJECTED
                    - ACCOUNT_LOCKED, ACCOUNT_UNLOCKED
                    
                    **Security:**
                    - PASSWORD_CHANGE, PASSWORD_RESET
                    - EMAIL_VERIFIED, PHONE_VERIFIED
                    - MFA_ENABLED, MFA_DISABLED
                    
                    **Authorization:**
                    - ROLE_ASSIGNED, ROLE_REVOKED
                    - PERMISSION_GRANTED, PERMISSION_REVOKED
                    - PERMISSION_CHECK
                    
                    **System:**
                    - BOOTSTRAP, CONFIGURATION_CHANGED
                    - FIRST_TIME_SETUP
                    
                    **Returns:**
                    - All logs matching the action type
                    - Sorted by timestamp (newest first)
                    - Across all users
                    - Includes metadata
                    
                    **Use Cases:**
                    - Security analysis (all failed logins)
                    - Compliance (all permission changes)
                    - Troubleshooting (all account locks)
                    - Pattern detection (login patterns)
                    - Audit specific operation type
                    
                    **Examples:**
```
                    GET /api/audit-logs/action/LOGIN_FAILED
                    → All failed login attempts
                    
                    GET /api/audit-logs/action/ROLE_ASSIGNED
                    → All role assignments
                    
                    GET /api/audit-logs/action/PERMISSION_CHECK
                    → All permission checks by admins
```
                    
                    **Performance:**
                    - Indexed by action type for fast retrieval
                    - Results may be large for common actions
                    - Consider additional filtering if needed
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Action-filtered logs retrieved",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "data": [
                                                {
                                                  "id": "log-789",
                                                  "action": "LOGIN_FAILED",
                                                  "userId": "user-456",
                                                  "timestamp": "2024-03-15T14:22:30Z",
                                                  "ipAddress": "192.168.1.100",
                                                  "metadata": {
                                                    "reason": "INVALID_PASSWORD",
                                                    "attemptCount": 3
                                                  }
                                                },
                                                {
                                                  "id": "log-790",
                                                  "action": "LOGIN_FAILED",
                                                  "userId": "user-789",
                                                  "timestamp": "2024-03-15T14:20:00Z",
                                                  "ipAddress": "192.168.1.105",
                                                  "metadata": {
                                                    "reason": "ACCOUNT_LOCKED"
                                                  }
                                                }
                                              ],
                                              "actionType": "LOGIN_FAILED",
                                              "count": 2,
                                              "timestamp": "2024-03-15T14:30:00Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid action type"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions"
            )
    })
    @GetMapping("/action/{actionType}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAuditLogsByAction(
            @Parameter(
                    description = "Action type to filter by",
                    required = true,
                    example = "LOGIN_FAILED",
                    schema = @Schema(implementation = ActionType.class)
            )
            @PathVariable ActionType actionType) {

        Instant requestTime = clock.instant();

        log.info("Fetching audit logs for action {} at {}", actionType, requestTime);

        List<AuditLogDTO> logs = auditLogService.getAuditLogsByAction(actionType);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", logs,
                "actionType", actionType.name(),
                "count", logs.size(),
                "timestamp", requestTime.toString()
        ));
    }

    /* =========================
       User Permissions Check
       ========================= */

    @Operation(
            summary = "Get User Permissions with Audit",
            description = """
                    Check user permissions and log the check for audit trail.
                    
                    **Purpose:**
                    - View a user's effective permissions
                    - Understand role-based access
                    - Verify permission grants
                    - Debug access issues
                    - Create audit trail of permission checks
                    
                    **Access Required:**
                    - ADMIN role
                    - Admin ID must be provided in X-Admin-Id header
                    
                    **Returns:**
                    - User's assigned roles
                    - Direct permissions
                    - Effective permissions (roles + direct)
                    - Permission check audit logged
                    
                    **Permission Resolution:**
                    Effective permissions = Role permissions + Additional permissions
                    
                    **Roles and Default Permissions:**
                    - **SUPER_ADMIN**: All system permissions
                    - **ADMIN**: User management, system config
                    - **MANAGER**: Team management, reports
                    - **USER**: Basic access
                    
                    **Audit Trail:**
                    This endpoint creates an audit log entry with:
                    - Who checked the permissions (admin ID)
                    - Whose permissions were checked (user ID)
                    - When the check occurred
                    - What permissions were found
                    
                    **Use Cases:**
                    - Troubleshooting access issues
                    - Verifying role assignments
                    - Security review
                    - Compliance documentation
                    - Debug permission problems
                    
                    **Headers Required:**
```
                    Authorization: Bearer <admin-token>
                    X-Admin-Id: admin-123
```
                    
                    **Example Response:**
                    The response shows:
                    - Assigned roles
                    - Additional permissions granted directly
                    - All effective permissions (combined)
                    - When and by whom the check was performed
                    
                    **Security:**
                    - Only admins can check permissions
                    - All checks are logged
                    - Cannot modify permissions (read-only)
                    - Admin identity tracked
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Permissions retrieved and check logged",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserPermissionsDTO.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "data": {
                                                "userId": "user-123",
                                                "roles": ["MANAGER", "USER"],
                                                "permissions": ["REPORT_VIEW"],
                                                "allPermissions": [
                                                  "USER_READ",
                                                  "USER_UPDATE",
                                                  "REPORT_VIEW",
                                                  "REPORT_CREATE",
                                                  "TEAM_MANAGE"
                                                ]
                                              },
                                              "checkedAt": "2024-03-15T14:30:00Z",
                                              "checkedBy": "admin-789"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Missing X-Admin-Id header"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "User not found"
            )
    })
    @GetMapping("/users/{userId}/permissions")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getUserPermissions(
            @Parameter(
                    description = "User ID to check permissions for",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,

            @Parameter(
                    description = "Admin performing the check (for audit trail)",
                    required = true,
                    example = "admin-789"
            )
            @RequestHeader("X-Admin-Id") String adminId) {

        Instant checkTime = clock.instant();

        log.info("Permission check at {} for user {} by admin {}", checkTime, userId, adminId);

        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    // resolveEffectivePermissions already returns Set<String>
                    var effectivePermissions = permissionProvider.resolveEffectivePermissions(user);
                    var roles = user.getRoleNames();

                    AuditEventLog event = new AuditEventLog();
                    event.setAction("PERMISSION_CHECK");
                    event.setPerformedBy(adminId);
                    event.setTargetUser(userId);
                    event.setTimestamp(checkTime);
                    event.setMetadata(Map.of(
                            "roles", roles,
                            "checkedPermissions", effectivePermissions
                    ));

                    // Build DTO using builder
                    UserPermissionsDTO dto = UserPermissionsDTO.builder()
                            .userId(userId)
                            .roles(roles)
                            .permissions(user.getAdditionalPermissions())
                            .allPermissions(effectivePermissions)
                            .build();

                    return auditLogService.logEventLog(event)
                            .thenReturn(ResponseEntity.ok(Map.of(
                                    "success", true,
                                    "data", dto,
                                    "checkedAt", checkTime.toString(),
                                    "checkedBy", adminId
                            )));
                });
    }
}