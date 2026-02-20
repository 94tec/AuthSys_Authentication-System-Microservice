package com.techStack.authSys.controller.admin;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.exception.authorization.AccessDeniedException;
import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.service.user.AdminService;
import com.techStack.authSys.util.validation.HelperUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Unified Admin Controller - Role-Based User Management
 *
 * Consolidated from 3 separate services into single, hierarchical architecture.
 *
 * ACCESS LEVELS:
 * =============
 * SUPER_ADMIN (100%): Full system access
 * ADMIN (75%): Restricted access (cannot manage admins)
 *
 * AUTHORIZATION HIERARCHY:
 * =======================
 * SUPER_ADMIN > ADMIN > MANAGER > USER
 * Rule: Can only manage users with LOWER privilege level
 *
 * @author TechStack Security Team
 * @version 2.0 - Unified Architecture
 */
@Slf4j
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Tag(
        name = "Unified Admin Operations",
        description = """
                **Consolidated administrative interface** for user lifecycle management.
                
                **Architecture:**
                Refactored from 3 separate services into single, role-based service:
                - AdminManagementService (deprecated)
                - AdminUserManagementService (deprecated)
                - UserApprovalService (deprecated)
                → AdminService (unified)
                
                **Access Level Matrix:**
                
                | Operation | SUPER_ADMIN | ADMIN | Notes |
                |-----------|-------------|-------|-------|
                | Create Admin | ✅ 100% | ❌ | SUPER_ADMIN only |
                | Approve User | ✅ 100% | ✅ 75% | Both (with restrictions) |
                | Approve Admin | ✅ | ❌ | SUPER_ADMIN only |
                | Suspend User | ✅ 100% | ✅ 75% | Both (with restrictions) |
                | Suspend Admin | ✅ | ❌ | SUPER_ADMIN only |
                | Force Password Reset | ✅ 100% | ✅ 75% | Both (with restrictions) |
                | View All Users | ✅ | ❌ | Filtered by role |
                | View Statistics | ✅ | ✅ | Filtered by role |
                
                **Hierarchical Permission Model:**
                - Can only manage users with LOWER privilege level
                - SUPER_ADMIN: Full access to all operations (100%)
                - ADMIN: Restricted access, cannot manage admins (75%)
                
                **Security Features:**
                - Method-level authorization (@PreAuthorize)
                - Runtime hierarchical permission checks
                - Comprehensive audit logging (who, what, when, why)
                - IP tracking and device fingerprinting
                - Session invalidation on sensitive operations
                
                **All endpoints require authentication + appropriate role**
                """
)
public class AdminController {

    private final AdminService adminService;
    private final DeviceVerificationService deviceService;
    private final Clock clock;

    /* =========================
       ADMIN CREATION (SUPER_ADMIN ONLY - 100%)
       ========================= */

    @Operation(
            summary = "Create Admin User (SUPER_ADMIN Only)",
            description = """
                    Create new administrative user with ADMIN role.
                    
                    **⚠️ SUPER_ADMIN ONLY - 100% Access Level**
                    
                    **Authorization:**
                    - Requires SUPER_ADMIN role
                    - Only SUPER_ADMIN can create other admins
                    - ADMIN cannot access this endpoint (403 Forbidden)
                    
                    **Process:**
                    1. Validate creator has SUPER_ADMIN role
                    2. Check email not already in use
                    3. Generate secure temporary password
                    4. Create admin user with ADMIN role
                    5. Set forcePasswordChange = true
                    6. Send welcome email with temp password
                    7. Enable MFA requirement
                    8. Log admin creation in audit trail
                    
                    **New Admin Receives:**
                    - ADMIN role with standard permissions (75% access)
                    - Temporary password via email
                    - Forced password change on first login
                    - MFA requirement enabled
                    - Phone verification required
                    
                    **Security:**
                    - Temporary password: 16 chars, alphanumeric + special
                    - Password expires after 24 hours if not changed
                    - Email verification required
                    - All admin creations logged
                    - IP address tracked
                    
                    **Use Cases:**
                    - Onboarding new admin staff
                    - Promoting user to admin role
                    - Creating system administrators
                    
                    **Email Template:**
                    Subject: "Admin Account Created"
                    - Welcome message
                    - Temporary password (one-time use)
                    - First-time setup instructions
                    - Security guidelines
                    - Support contact
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "201",
                    description = "Admin created successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Admin created successfully. Credentials sent to email.",
                                              "data": "admin-user-123",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid request or email already exists",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Email already in use",
                                              "errorCode": "BAD_REQUEST",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions (requires SUPER_ADMIN)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Only SUPER_ADMIN can create admin users",
                                              "errorCode": "FORBIDDEN",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/users/create-admin")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<String>>> createAdmin(
            @Parameter(
                    description = "Admin user registration details",
                    required = true,
                    schema = @Schema(implementation = UserRegistrationDTO.class)
            )
            @Valid @RequestBody UserRegistrationDTO userDto,

            Authentication authentication,
            ServerWebExchange exchange
    ) {
        Instant startTime = clock.instant();
        String ipAddress = deviceService.extractClientIp(exchange);
        String creatorId = authentication.getName();
        Roles creatorRole = extractRole(authentication);

        log.info("🔐 [ADMIN CREATION] Request by {} ({}) for: {} at {}",
                creatorId, creatorRole, HelperUtils.maskEmail(userDto.getEmail()), startTime);

        return adminService.createAdmin(userDto, creatorId, creatorRole, ipAddress)
                .map(admin -> {
                    Duration duration = Duration.between(startTime, clock.instant());

                    log.info("✅ [ADMIN CREATION] Admin created in {} - ID: {} at {}",
                            duration, admin.getId(), clock.instant());

                    return ResponseEntity.status(HttpStatus.CREATED)
                            .body(new ApiResponse<>(
                                    true,
                                    "Admin created successfully. Credentials sent to email.",
                                    admin.getId(),
                                    clock.instant()
                            ));
                })
                // ✅ Handle authorization failure (shouldn't happen due to @PreAuthorize, but defensive)
                .onErrorResume(AccessDeniedException.class, e -> {
                    log.warn("🚫 [ADMIN CREATION] Access denied for {} ({}): {}",
                            creatorId, creatorRole, e.getMessage());

                    return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(ApiResponse.<String>error(e.getMessage(), "FORBIDDEN")));
                })
                // ✅ Handle duplicate email
                .onErrorResume(IllegalStateException.class, e -> {
                    log.warn("⚠️ [ADMIN CREATION] Invalid state: {}", e.getMessage());

                    return Mono.just(ResponseEntity.badRequest()
                            .body(ApiResponse.<String>error(e.getMessage(), "BAD_REQUEST")));
                })
                // ✅ Handle email sending failure (non-fatal)
                .onErrorResume(EmailSendingException.class, e -> {
                    log.error("📧 [ADMIN CREATION] Email failed but admin created: {}",
                            e.getMessage());

                    return Mono.just(ResponseEntity.status(HttpStatus.CREATED)
                            .body(ApiResponse.<String>error(
                                    "Admin created but email failed. Contact admin to resend credentials.",
                                    "EMAIL_FAILED"
                            )));
                })
                // ✅ Catch-all for unexpected errors
                .onErrorResume(e -> {
                    Duration duration = Duration.between(startTime, clock.instant());

                    log.error("❌ [ADMIN CREATION] Failed after {} for {}: {}",
                            duration, HelperUtils.maskEmail(userDto.getEmail()), e.getMessage(), e);

                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(ApiResponse.<String>error(
                                    "Failed to create admin. Please try again.",
                                    "SERVER_ERROR"
                            )));
                });
    }

    /* =========================
       USER APPROVAL (ADMIN & SUPER_ADMIN - 75%/100%)
       ========================= */

    @Operation(
            summary = "Approve Pending User",
            description = """
                    Approve user account from PENDING status to ACTIVE status.
                    
                    **Authorization: ADMIN & SUPER_ADMIN**
                    **Access Levels:**
                    - ADMIN (75%): Can approve regular users only
                    - SUPER_ADMIN (100%): Can approve all users including admins
                    
                    **Process:**
                    1. Validate approver has appropriate role
                    2. Check target user status (must be PENDING)
                    3. Verify approver authority (hierarchical check)
                    4. Activate user account
                    5. Grant role-based permissions
                    6. Send welcome email
                    7. Log approval in audit trail
                    
                    **Hierarchical Rules:**
                    - ADMIN cannot approve users with ADMIN or SUPER_ADMIN roles
                    - SUPER_ADMIN can approve any user
                    - System enforces: Can only approve users with LOWER privilege
                    
                    **Actions Performed:**
                    - Status: PENDING → ACTIVE
                    - Send welcome email with login instructions
                    - Grant role-based default permissions
                    - Enable account access
                    - Create audit log entry
                    
                    **Use Cases:**
                    - New user registration approval
                    - Post-verification account activation
                    - Manual approval workflow completion
                    
                    **Error Scenarios:**
                    - User already active (400)
                    - User not found (404)
                    - Insufficient permission to approve admin users (403)
                    - User status is SUSPENDED or REJECTED (400)
                    
                    **Example Workflow:**
```
                    1. User registers → Status: PENDING
                    2. Admin reviews application
                    3. Admin approves → Status: ACTIVE
                    4. User receives welcome email
                    5. User can now log in
```
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "User approved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "User approved successfully",
                                              "data": null,
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid state (user already active, suspended, or rejected)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "User is not in pending status",
                                              "errorCode": "INVALID_STATE",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions (ADMIN cannot approve admin users)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "ADMIN users cannot approve users with ADMIN or SUPER_ADMIN roles",
                                              "errorCode": "FORBIDDEN",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "User not found"
            )
    })
    @PostMapping("/users/{userId}/approve")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<Void>>> approveUser(
            @Parameter(
                    description = "User ID to approve",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,

            Authentication authentication
    ) {
        String approverId = authentication.getName();
        Roles approverRole = extractRole(authentication);

        log.info("✅ [APPROVE USER] Request for {} by {} ({})",
                userId, approverId, approverRole);

        return adminService.approveUser(userId, approverId, approverRole)
                .map(user -> ResponseEntity.ok(
                        ApiResponse.<Void>success(
                                "User approved successfully",
                                null,
                                clock.instant()
                        )))
                .onErrorResume(AccessDeniedException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(ApiResponse.<Void>error(e.getMessage(), "FORBIDDEN"))))
                .onErrorResume(IllegalStateException.class, e ->
                        Mono.just(ResponseEntity.badRequest()
                                .body(ApiResponse.<Void>error(e.getMessage(), "INVALID_STATE"))))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.<Void>error(
                                        "Approval failed",
                                        "SERVER_ERROR"
                                ))));
    }

    @Operation(
            summary = "Reject Pending User",
            description = """
                    Reject user account and permanently delete from system.
                    
                    **Authorization: ADMIN & SUPER_ADMIN**
                    **Access Levels:**
                    - ADMIN (75%): Can reject regular users only
                    - SUPER_ADMIN (100%): Can reject all users
                    
                    **⚠️ DESTRUCTIVE OPERATION - CANNOT BE UNDONE**
                    
                    **Process:**
                    1. Validate rejector authority
                    2. Verify user is in PENDING status
                    3. Check hierarchical permission
                    4. Send rejection notification email
                    5. Delete user from Firestore
                    6. Delete from Firebase Auth
                    7. Log rejection in audit trail
                    8. Remove all associated data
                    
                    **Reason Required:**
                    - Must provide rejection reason
                    - Included in rejection email
                    - Logged in audit trail
                    - Helps user understand decision
                    
                    **Actions Performed:**
                    - Send rejection notification with reason
                    - Delete user account from database
                    - Remove from Firebase Authentication
                    - Clean up user sessions
                    - Delete uploaded documents
                    - Remove from pending approval queue
                    - Create permanent audit record
                    
                    **Rejection Email Includes:**
                    - Rejection notice
                    - Reason provided by admin
                    - Appeal process (if applicable)
                    - Support contact information
                    
                    **Use Cases:**
                    - Failed background check
                    - Incomplete registration
                    - Policy violations
                    - Duplicate account
                    - Fraudulent registration
                    
                    **Security:**
                    - Requires explicit reason
                    - Audit logged with full context
                    - Email notification sent
                    - Cannot reject already active users
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "User rejected and deleted successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "User rejected and account deleted",
                                              "data": null,
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "ADMIN users cannot reject users with ADMIN or SUPER_ADMIN roles",
                                              "errorCode": "FORBIDDEN",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/users/{userId}/reject")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<Void>>> rejectUser(
            @Parameter(
                    description = "User ID to reject",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,

            @Parameter(
                    description = "Reason for rejection (required)",
                    required = true,
                    example = "Incomplete registration documents"
            )
            @RequestParam String reason,

            Authentication authentication
    ) {
        String rejecterId = authentication.getName();
        Roles rejectorRole = extractRole(authentication);

        log.warn("🚫 [REJECT USER] Request for {} by {} ({}) - Reason: {}",
                userId, rejecterId, rejectorRole, reason);

        return adminService.rejectUser(userId, rejecterId, rejectorRole, reason)
                .then(Mono.just(ResponseEntity.ok(
                        ApiResponse.<Void>success(
                                "User rejected and account deleted",
                                null,
                                clock.instant()
                        ))))
                .onErrorResume(AccessDeniedException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(ApiResponse.<Void>error(e.getMessage(), "FORBIDDEN"))))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.<Void>error(
                                        "Rejection failed",
                                        "SERVER_ERROR"
                                ))));
    }

    /* =========================
       USER LIFECYCLE MANAGEMENT (ADMIN & SUPER_ADMIN)
       ========================= */

    @Operation(
            summary = "Suspend User Account",
            description = """
                    Suspend user account (temporarily disable access).
                    
                    **Authorization: ADMIN & SUPER_ADMIN**
                    **Access Levels:**
                    - ADMIN (75%): Can suspend regular users only
                    - SUPER_ADMIN (100%): Can suspend all users including admins
                    
                    **Process:**
                    1. Validate performer authority
                    2. Check hierarchical permission
                    3. Verify reason provided
                    4. Set status to SUSPENDED
                    5. Invalidate all active sessions
                    6. Prevent new logins
                    7. Send suspension notification
                    8. Log in audit trail
                    
                    **Actions Performed:**
                    - Status: ACTIVE → SUSPENDED
                    - Invalidate all user sessions
                    - Block login attempts
                    - Send suspension notification email
                    - Log suspension reason
                    - Preserve user data (not deleted)
                    
                    **Reason Required:**
                    - Must provide clear reason
                    - Included in notification email
                    - Logged for compliance
                    - Helps user understand why
                    
                    **Use Cases:**
                    - Policy violations
                    - Security incidents
                    - Pending investigation
                    - Temporary access removal
                    - Account compromise suspected
                    
                    **Suspension Email:**
                    - Notification of suspension
                    - Reason for suspension
                    - Duration (if temporary)
                    - Appeal process
                    - Reactivation conditions
                    - Support contact
                    
                    **Reversible:**
                    - Can be reactivated by admin
                    - User data preserved
                    - History maintained
                    - Audit trail intact
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "User suspended successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions (ADMIN cannot suspend admin users)"
            )
    })
    @PostMapping("/users/{userId}/suspend")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<Void>>> suspendUser(
            @Parameter(
                    description = "User ID to suspend",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,

            @Parameter(
                    description = "Reason for suspension (required)",
                    required = true,
                    example = "Multiple policy violations"
            )
            @RequestParam String reason,

            Authentication authentication
    ) {
        String performerId = authentication.getName();
        Roles performerRole = extractRole(authentication);

        log.warn("⏸️ [SUSPEND USER] Request for {} by {} ({}) - Reason: {}",
                userId, performerId, performerRole, reason);

        return adminService.suspendUser(userId, performerId, performerRole, reason)
                .then(Mono.just(ResponseEntity.ok(
                        ApiResponse.<Void>success(
                                "User suspended successfully",
                                null,
                                clock.instant()
                        ))))
                .onErrorResume(AccessDeniedException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(ApiResponse.<Void>error(e.getMessage(), "FORBIDDEN"))))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.<Void>error(
                                        "Suspension failed",
                                        "SERVER_ERROR"
                                ))));
    }

    @Operation(
            summary = "Reactivate Suspended User",
            description = """
                    Reactivate previously suspended user account.
                    
                    **Authorization: ADMIN & SUPER_ADMIN**
                    **Access Levels:**
                    - ADMIN (75%): Can reactivate regular users only
                    - SUPER_ADMIN (100%): Can reactivate all users
                    
                    **Process:**
                    1. Validate performer authority
                    2. Verify user is SUSPENDED
                    3. Check hierarchical permission
                    4. Set status to ACTIVE
                    5. Restore access permissions
                    6. Send reactivation notification
                    7. Log in audit trail
                    
                    **Actions Performed:**
                    - Status: SUSPENDED → ACTIVE
                    - Restore login capability
                    - Re-enable permissions
                    - Send reactivation email
                    - Create audit log entry
                    
                    **Use Cases:**
                    - Suspension period ended
                    - Issue resolved
                    - Investigation completed
                    - Appeal approved
                    - Reinstatement after compliance
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "User reactivated successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions"
            )
    })
    @PostMapping("/users/{userId}/reactivate")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<Void>>> reactivateUser(
            @Parameter(
                    description = "User ID to reactivate",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,

            Authentication authentication
    ) {
        String performerId = authentication.getName();
        Roles performerRole = extractRole(authentication);

        log.info("▶️ [REACTIVATE USER] Request for {} by {} ({})",
                userId, performerId, performerRole);

        return adminService.reactivateUser(userId, performerId, performerRole)
                .then(Mono.just(ResponseEntity.ok(
                        ApiResponse.<Void>success(
                                "User reactivated successfully",
                                null,
                                clock.instant()
                        ))))
                .onErrorResume(AccessDeniedException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(ApiResponse.<Void>error(e.getMessage(), "FORBIDDEN"))))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.<Void>error(
                                        "Reactivation failed",
                                        "SERVER_ERROR"
                                ))));
    }

    @Operation(
            summary = "Force Password Reset",
            description = """
                    Force user to reset password on next login.
                    
                    **Authorization: ADMIN & SUPER_ADMIN**
                    **Access Levels:**
                    - ADMIN (75%): Can reset for regular users only
                    - SUPER_ADMIN (100%): Can reset for all users
                    
                    **Process:**
                    1. Validate performer authority
                    2. Check hierarchical permission
                    3. Set forcePasswordChange = true
                    4. Invalidate current password
                    5. Send password reset notification
                    6. Log in audit trail
                    
                    **User Experience:**
                    - Next login: redirected to password reset
                    - Cannot access system until password changed
                    - Receives email with instructions
                    - OTP verification required
                    
                    **Use Cases:**
                    - Security breach suspected
                    - Password compromised
                    - Compliance requirement
                    - Admin-initiated security measure
                    - Account recovery assistance
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password reset forced successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions"
            )
    })
    @PostMapping("/users/{userId}/reset-password")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<Void>>> forcePasswordReset(
            @Parameter(
                    description = "User ID to force password reset",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,

            Authentication authentication
    ) {
        String performerId = authentication.getName();
        Roles performerRole = extractRole(authentication);

        log.info("🔑 [FORCE PASSWORD RESET] Request for {} by {} ({})",
                userId, performerId, performerRole);

        return adminService.forcePasswordReset(userId, performerId, performerRole)
                .then(Mono.just(ResponseEntity.ok(
                        ApiResponse.<Void>success(
                                "Password reset forced. User will be prompted on next login.",
                                null,
                                clock.instant()
                        ))))
                .onErrorResume(AccessDeniedException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(ApiResponse.<Void>error(e.getMessage(), "FORBIDDEN"))))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.<Void>error(
                                        "Password reset failed",
                                        "SERVER_ERROR"
                                ))));
    }

    /* =========================
       USER QUERIES (ADMIN & SUPER_ADMIN)
       ========================= */

    @Operation(
            summary = "List Users",
            description = """
                    Get paginated list of users with optional filters.
                    
                    **Authorization: ADMIN & SUPER_ADMIN**
                    **Access Levels:**
                    - ADMIN (75%): Sees regular users only (filtered)
                    - SUPER_ADMIN (100%): Sees all users including admins
                    
                    **Filters:**
                    - Status (ACTIVE, PENDING, SUSPENDED, REJECTED)
                    - Role (USER, MANAGER, ADMIN, SUPER_ADMIN)
                    - Date range (registration date)
                    - Search (name, email)
                    
                    **Response:**
                    - Paginated list of users
                    - Total count
                    - Filter metadata
                    - Role-filtered based on requester
                    
                    **ADMIN Restrictions:**
                    - Cannot see users with ADMIN or SUPER_ADMIN roles
                    - Results automatically filtered
                    - Statistics exclude admin users
                    
                    **SUPER_ADMIN Permissions:**
                    - See all users regardless of role
                    - Complete user details
                    - Unfiltered statistics
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Users retrieved successfully (role-filtered)"
            )
    })
    @GetMapping("/users")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public Flux<User> listUsers(
            @Parameter(
                    description = "Filter by user status",
                    example = "ACTIVE"
            )
            @RequestParam(required = false) UserStatus status,

            Authentication authentication
    ) {
        Roles performerRole = extractRole(authentication);

        log.info("📋 [LIST USERS] Request by {} - Status filter: {}",
                performerRole, status != null ? status : "ALL");

        AdminService.UserQueryFilters filters = new AdminService.UserQueryFilters(
                status != null ? status : UserStatus.ACTIVE,
                java.util.Optional.empty(),
                java.util.Optional.empty(),
                java.util.Optional.empty()
        );

        return adminService.findUsers(performerRole, filters);
    }

    @Operation(
            summary = "Get User Statistics",
            description = """
                    Get user count statistics by status and role.
                    
                    **Authorization: ADMIN & SUPER_ADMIN**
                    **Access Levels:**
                    - ADMIN (75%): Statistics for regular users only
                    - SUPER_ADMIN (100%): Complete system statistics
                    
                    **Returns:**
                    - Total users
                    - Count by status (ACTIVE, PENDING, SUSPENDED)
                    - Count by role (USER, MANAGER, ADMIN)
                    - Growth metrics
                    - Registration trends
                    
                    **Filtering:**
                    - ADMIN: Excludes admin-level users from counts
                    - SUPER_ADMIN: Includes all users
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Statistics retrieved (role-filtered)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Statistics retrieved successfully",
                                              "data": {
                                                "totalUsers": 1250,
                                                "activeUsers": 980,
                                                "pendingUsers": 45,
                                                "suspendedUsers": 12,
                                                "rejectedUsers": 213
                                              },
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @GetMapping("/users/statistics")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<Map<String, Long>>>> getUserStatistics(
            Authentication authentication
    ) {
        Roles performerRole = extractRole(authentication);

        log.info("📊 [USER STATISTICS] Request by {}", performerRole);

        return adminService.getUserStatistics(performerRole)
                .map(stats -> ResponseEntity.ok(
                        ApiResponse.success(
                                "Statistics retrieved successfully",
                                stats,
                                clock.instant()
                        )))
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.<Map<String, Long>>error(
                                        "Failed to retrieve statistics",
                                        "SERVER_ERROR"
                                ))));
    }

    /* =========================
       HELPER METHODS
       ========================= */

    /**
     * Extract role from Spring Security Authentication
     *
     * @param authentication Spring Security Authentication object
     * @return Highest role found (SUPER_ADMIN > ADMIN > USER)
     */
    private Roles extractRole(Authentication authentication) {
        if (authentication.getAuthorities().contains(
                new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))) {
            return Roles.SUPER_ADMIN;
        }
        if (authentication.getAuthorities().contains(
                new SimpleGrantedAuthority("ROLE_ADMIN"))) {
            return Roles.ADMIN;
        }
        if (authentication.getAuthorities().contains(
                new SimpleGrantedAuthority("ROLE_MANAGER"))) {
            return Roles.MANAGER;
        }
        return Roles.USER;
    }
}
