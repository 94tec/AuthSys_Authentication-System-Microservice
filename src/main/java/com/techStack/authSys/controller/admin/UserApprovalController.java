package com.techStack.authSys.controller.admin;

import com.techStack.authSys.dto.internal.RequesterContext;
import com.techStack.authSys.dto.internal.SecurityContext;
import com.techStack.authSys.dto.response.PendingUserResponse;
import com.techStack.authSys.models.user.ApprovalLevel;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.security.context.SecurityContextService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.user.UserApprovalService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * User Approval Controller
 *
 * Handles user approval workflows with hierarchical authority validation.
 * Supports role-based access control for SUPER_ADMIN, ADMIN, and MANAGER roles.
 * Uses Clock for deterministic timestamp tracking.
 *
 * @version 1.0
 * @since 2026-02-14
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
@Tag(
        name = "User Approval Management",
        description = "APIs for managing user approval workflows with hierarchical authority validation. " +
                "Supports pending user review, approval/rejection operations, and approval statistics. " +
                "Requires SUPER_ADMIN, ADMIN, or MANAGER role."
)
@SecurityRequirement(name = "Bearer Authentication")
public class UserApprovalController {

    /* =========================
       Dependencies
       ========================= */

    private final RoleAssignmentService roleAssignmentService;
    private final UserApprovalService userApprovalService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final SecurityContextService securityContextService;
    private final Clock clock;

    /* =========================
       Get Pending Users
       ========================= */

    /**
     * Get pending users with comprehensive approval context
     */
    @GetMapping(value = "/pending", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    @Operation(
            summary = "Get pending users",
            description = "Retrieves all users pending approval with comprehensive context including " +
                    "approval authority validation. Returns whether the current user can approve " +
                    "each pending user based on role hierarchy.",
            tags = {"User Approval Management"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successfully retrieved pending users",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PendingUserResponse.class),
                            examples = @ExampleObject(
                                    name = "Pending users response",
                                    value = """
                        [
                          {
                            "id": "user-123",
                            "email": "john.doe@example.com",
                            "firstName": "John",
                            "lastName": "Doe",
                            "roles": ["USER", "MANAGER"],
                            "status": "PENDING_APPROVAL",
                            "approvalLevel": "PENDING_L1",
                            "createdAt": "2026-02-14T10:00:00Z",
                            "department": "Engineering",
                            "canApprove": true,
                            "requesterContext": {
                              "requesterEmail": "admin@example.com",
                              "requesterRole": "ADMIN",
                              "timestamp": "2026-02-14T10:15:00Z"
                            }
                          }
                        ]
                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized - Invalid or missing authentication token",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Unauthorized access",
                          "errorCode": "UNAUTHORIZED"
                        }
                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - User lacks required role (SUPER_ADMIN, ADMIN, or MANAGER)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Access denied",
                          "errorCode": "FORBIDDEN"
                        }
                        """
                            )
                    )
            )
    })
    public Flux<PendingUserResponse> getPendingUsersWithApprovalContext(
            @Parameter(hidden = true) Authentication authentication) {

        Instant requestTime = clock.instant();

        return securityContextService.getCurrentSecurityContext(authentication)
                .flatMapMany(securityContext -> {
                    log.info("📋 Fetching pending users at {} - Requester: {} ({})",
                            requestTime, securityContext.getRequesterEmail(),
                            securityContext.getRequesterRole());

                    return firebaseServiceAuth.findAllUsersByStatus(UserStatus.PENDING_APPROVAL)
                            .map(user -> buildPendingUserResponse(user, securityContext))
                            .doOnNext(response ->
                                    log.debug("👤 Pending user processed: {} | Can Approve: {}",
                                            response.getEmail(), response.isCanApprove()));
                });
    }

    /**
     * Build pending user response
     */
    private PendingUserResponse buildPendingUserResponse(User user, SecurityContext securityContext) {
        Instant now = clock.instant();

        return PendingUserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles())
                .status(user.getStatus())
                .approvalLevel(user.getApprovalLevel() != null ?
                        user.getApprovalLevel() : ApprovalLevel.PENDING_L1)
                .createdAt(user.getCreatedAt() != null ? user.getCreatedAt() : now)
                .department(user.getDepartment() != null ? user.getDepartment() : "")
                .canApprove(roleAssignmentService.canApproveUser(securityContext, user))
                .requesterContext(buildRequesterContext(securityContext, now))
                .build();
    }

    /**
     * Build requester context
     */
    private RequesterContext buildRequesterContext(SecurityContext securityContext, Instant timestamp) {
        return RequesterContext.builder()
                .requesterEmail(securityContext.getRequesterEmail())
                .requesterRole(securityContext.getRequesterRole())
                .timestamp(timestamp)
                .build();
    }

    /* =========================
       Approve User
       ========================= */

    /**
     * Approve a pending user with hierarchical authority validation
     */
    @PostMapping(value = "/{userId}/approve", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    @Operation(
            summary = "Approve pending user",
            description = "Approves a user account with hierarchical authority validation. " +
                    "The approver must have sufficient authority based on role hierarchy:\n" +
                    "- SUPER_ADMIN can approve any user\n" +
                    "- ADMIN can approve MANAGER and USER roles\n" +
                    "- MANAGER can approve USER roles only\n\n" +
                    "Upon successful approval, the user account is activated and granted access.",
            tags = {"User Approval Management"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User approved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Approval success",
                                    value = """
                        {
                          "success": true,
                          "message": "User approved successfully",
                          "data": {
                            "userId": "user-123",
                            "email": "john.doe@example.com",
                            "status": "ACTIVE",
                            "enabled": true,
                            "roles": ["USER", "MANAGER"],
                            "permissions": ["READ", "WRITE"],
                            "approvedBy": "admin@example.com",
                            "approvedAt": "2026-02-14T10:30:00Z"
                          }
                        }
                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Bad Request - User cannot be approved (already approved, rejected, or invalid state)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "User is already approved"
                        }
                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - Insufficient authority to approve this user",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Insufficient authority to approve this user",
                          "details": "MANAGER cannot approve ADMIN role"
                        }
                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "User not found"
                        }
                        """
                            )
                    )
            )
    })
    public Mono<ResponseEntity<Map<String, Object>>> approveUser(
            @Parameter(
                    description = "ID of the user to approve",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,
            @Parameter(hidden = true) Authentication authentication) {

        Instant approvalTime = clock.instant();
        String approverEmail = authentication.getName();
        Roles approverRole = roleAssignmentService.extractHighestRole(authentication);

        log.info("👤 Approval request at {} for user {} by {} ({})",
                approvalTime, userId, approverEmail, approverRole);

        return userApprovalService.approveUserAccount(userId, approverEmail, approverRole)
                .map(user -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ User {} approved successfully at {} by {}",
                            user.getEmail(), completionTime, approverEmail);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "User approved successfully",
                            "data", Map.of(
                                    "userId", user.getId(),
                                    "email", user.getEmail(),
                                    "status", user.getStatus().name(),
                                    "enabled", user.isEnabled(),
                                    "roles", user.getRoles(),
                                    "permissions", user.getAdditionalPermissions() != null ?
                                            user.getAdditionalPermissions() : List.of(),
                                    "approvedBy", approverEmail,
                                    "approvedAt", user.getApprovedAt() != null ?
                                            user.getApprovedAt().toString() : completionTime.toString()
                            )
                    ));
                })
                .onErrorResume(SecurityException.class, e -> {
                    log.warn("🚫 Insufficient authority at {}: {} cannot approve user {} - {}",
                            clock.instant(), approverRole, userId, e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of(
                                    "success", false,
                                    "message", "Insufficient authority to approve this user",
                                    "details", e.getMessage()
                            )));
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    log.warn("⚠️ Cannot approve user {} at {}: {}",
                            userId, clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Map.of(
                                    "success", false,
                                    "message", e.getMessage()
                            )));
                })
                .onErrorResume(e -> {
                    log.error("❌ Error approving user {} at {}: {}",
                            userId, clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of(
                                    "success", false,
                                    "message", "Failed to approve user: " + e.getMessage()
                            )));
                });
    }

    /* =========================
       Reject User
       ========================= */

    /**
     * Reject a pending user with reason tracking
     */
    @PostMapping(value = "/{userId}/reject",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    @Operation(
            summary = "Reject pending user",
            description = "Rejects a pending user account and removes them from the system. " +
                    "Requires hierarchical authority similar to approval. " +
                    "A rejection reason must be provided for audit purposes. " +
                    "The user will be permanently removed from the database.",
            tags = {"User Approval Management"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User rejected successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Rejection success",
                                    value = """
                        {
                          "success": true,
                          "message": "User rejected and removed from system",
                          "data": {
                            "userId": "user-123",
                            "rejectedBy": "admin@example.com",
                            "rejectedAt": "2026-02-14T10:45:00Z",
                            "reason": "Incomplete documentation"
                          }
                        }
                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Bad Request - User cannot be rejected (invalid state)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "User is already active and cannot be rejected"
                        }
                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - Insufficient authority to reject this user",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Insufficient authority to reject this user",
                          "details": "MANAGER cannot reject ADMIN role"
                        }
                        """
                            )
                    )
            )
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Rejection details",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = Map.class),
                    examples = @ExampleObject(
                            name = "Rejection request",
                            value = """
                    {
                      "reason": "Incomplete documentation provided"
                    }
                    """
                    )
            )
    )
    public Mono<ResponseEntity<Map<String, Object>>> rejectUser(
            @Parameter(
                    description = "ID of the user to reject",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,
            @RequestBody Map<String, String> request,
            @Parameter(hidden = true) Authentication authentication) {

        Instant rejectionTime = clock.instant();
        String rejectorEmail = authentication.getName();
        Roles rejectorRole = roleAssignmentService.extractHighestRole(authentication);
        String reason = request.getOrDefault("reason", "No reason provided");

        log.info("❌ Rejection request at {} for user {} by {} ({}) - Reason: {}",
                rejectionTime, userId, rejectorEmail, rejectorRole, reason);

        return userApprovalService.rejectUserAccount(userId, rejectorEmail, rejectorRole, reason)
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ User {} rejected at {}", userId, completionTime);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "User rejected and removed from system",
                            "data", Map.of(
                                    "userId", userId,
                                    "rejectedBy", rejectorEmail,
                                    "rejectedAt", completionTime.toString(),
                                    "reason", reason
                            )
                    ));
                }))
                .onErrorResume(SecurityException.class, e -> {
                    log.warn("🚫 Insufficient authority at {}: {} cannot reject user {} - {}",
                            clock.instant(), rejectorRole, userId, e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of(
                                    "success", false,
                                    "message", "Insufficient authority to reject this user",
                                    "details", e.getMessage()
                            )));
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    log.warn("⚠️ Cannot reject user {} at {}: {}",
                            userId, clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Map.of(
                                    "success", false,
                                    "message", e.getMessage()
                            )));
                })
                .onErrorResume(e -> {
                    log.error("❌ Error rejecting user {} at {}: {}",
                            userId, clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of(
                                    "success", false,
                                    "message", "Failed to reject user: " + e.getMessage()
                            )));
                });
    }

    /* =========================
       Get User Details
       ========================= */

    /**
     * Get user details by ID
     */
    @GetMapping(value = "/{userId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    @Operation(
            summary = "Get user details",
            description = "Retrieves detailed information about a specific user by ID. " +
                    "Includes approval status, roles, permissions, and whether the current user " +
                    "has authority to approve this user.",
            tags = {"User Approval Management"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User details retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "User details response",
                                    value = """
                        {
                          "success": true,
                          "data": {
                            "id": "user-123",
                            "email": "john.doe@example.com",
                            "firstName": "John",
                            "lastName": "Doe",
                            "roles": ["USER", "MANAGER"],
                            "status": "ACTIVE",
                            "enabled": true,
                            "approvalLevel": "Approved",
                            "createdAt": "2026-02-14T10:00:00Z",
                            "approvedAt": "2026-02-14T10:30:00Z",
                            "approvedBy": "admin@example.com",
                            "department": "Engineering",
                            "canApprove": false
                          },
                          "timestamp": "2026-02-14T11:00:00Z"
                        }
                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User not found",
                    content = @Content(mediaType = "application/json")
            )
    })
    public Mono<ResponseEntity<Map<String, Object>>> getUserById(
            @Parameter(
                    description = "ID of the user to retrieve",
                    required = true,
                    example = "user-123"
            )
            @PathVariable String userId,
            @Parameter(hidden = true) Authentication authentication) {

        Instant requestTime = clock.instant();

        log.debug("Fetching user details at {} for ID: {}", requestTime, userId);

        return securityContextService.getCurrentSecurityContext(authentication)
                .flatMap(securityContext ->
                        firebaseServiceAuth.getUserById(userId)
                                .map(user -> {
                                    Map<String, Object> data = Map.ofEntries(
                                            Map.entry("id", user.getId()),
                                            Map.entry("email", user.getEmail()),
                                            Map.entry("firstName", user.getFirstName()),
                                            Map.entry("lastName", user.getLastName()),
                                            Map.entry("roles", user.getRoles()),
                                            Map.entry("status", user.getStatus().name()),
                                            Map.entry("enabled", user.isEnabled()),
                                            Map.entry("approvalLevel", user.getApprovalLevel() != null ?
                                                    user.getApprovalLevel().getDisplayName() : ""),
                                            Map.entry("createdAt", user.getCreatedAt() != null ?
                                                    user.getCreatedAt().toString() : ""),
                                            Map.entry("approvedAt", user.getApprovedAt() != null ?
                                                    user.getApprovedAt().toString() : ""),
                                            Map.entry("approvedBy", user.getApprovedBy() != null ?
                                                    user.getApprovedBy() : ""),
                                            Map.entry("department", user.getDepartment() != null ?
                                                    user.getDepartment() : ""),
                                            Map.entry("canApprove",
                                                    roleAssignmentService.canApproveUser(securityContext, user))
                                    );

                                    return ResponseEntity.ok(
                                            Map.of(
                                                    "success", true,
                                                    "data", data,
                                                    "timestamp", clock.instant().toString()
                                            )
                                    );
                                })
                )
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    /* =========================
       Get All Users
       ========================= */

    /**
     * Get all users with optional status filter
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    @Operation(
            summary = "Get all users",
            description = "Retrieves all users with optional status filtering. " +
                    "Returns basic user information including ID, email, name, roles, and status. " +
                    "Use the status query parameter to filter by user status.",
            tags = {"User Approval Management"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Users retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "All users response",
                                    value = """
                        [
                          {
                            "id": "user-123",
                            "email": "john.doe@example.com",
                            "firstName": "John",
                            "lastName": "Doe",
                            "roles": ["USER"],
                            "status": "ACTIVE",
                            "enabled": true,
                            "createdAt": "2026-02-14T10:00:00Z"
                          },
                          {
                            "id": "user-456",
                            "email": "jane.smith@example.com",
                            "firstName": "Jane",
                            "lastName": "Smith",
                            "roles": ["USER", "MANAGER"],
                            "status": "PENDING_APPROVAL",
                            "enabled": false,
                            "createdAt": "2026-02-14T11:00:00Z"
                          }
                        ]
                        """
                            )
                    )
            )
    })
    public Flux<Map<String, Object>> getAllUsers(
            @Parameter(
                    description = "Filter users by status (PENDING_APPROVAL, ACTIVE, LOCKED, REJECTED, DEACTIVATED)",
                    required = false,
                    example = "ACTIVE"
            )
            @RequestParam(required = false) String status,
            @Parameter(hidden = true) Authentication authentication) {

        Instant requestTime = clock.instant();
        Roles approverRole = roleAssignmentService.extractHighestRole(authentication);

        log.info("Fetching all users at {} - Requester role: {}, Status filter: {}",
                requestTime, approverRole, status);

        Flux<User> userFlux;
        if (status != null) {
            try {
                UserStatus userStatus = UserStatus.valueOf(status.toUpperCase());
                userFlux = firebaseServiceAuth.findAllUsersByStatus(userStatus);
            } catch (IllegalArgumentException e) {
                log.warn("⚠️ Invalid status filter at {}: {}", requestTime, status);
                return Flux.empty();
            }
        } else {
            userFlux = firebaseServiceAuth.findAllUsers();
        }

        return userFlux.map(user -> Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "firstName", user.getFirstName(),
                "lastName", user.getLastName(),
                "roles", user.getRoles(),
                "status", user.getStatus().name(),
                "enabled", user.isEnabled(),
                "createdAt", user.getCreatedAt() != null ?
                        user.getCreatedAt().toString() : requestTime.toString()
        ));
    }

    /* =========================
       Approval Statistics
       ========================= */

    /**
     * Get approval statistics
     */
    @GetMapping(value = "/stats", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    @Operation(
            summary = "Get approval statistics",
            description = "Retrieves statistics about user approvals including pending and active user counts. " +
                    "Provides a summary of pending users with their email, roles, and creation date. " +
                    "Useful for monitoring approval queue and system activity.",
            tags = {"User Approval Management"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Statistics retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Approval statistics",
                                    value = """
                        {
                          "success": true,
                          "data": {
                            "pendingCount": 3,
                            "activeCount": 45,
                            "timestamp": "2026-02-14T11:30:00Z",
                            "pendingUsers": [
                              {
                                "email": "new.user1@example.com",
                                "roles": ["USER"],
                                "createdAt": "2026-02-14T10:00:00Z"
                              },
                              {
                                "email": "new.user2@example.com",
                                "roles": ["USER", "MANAGER"],
                                "createdAt": "2026-02-14T10:15:00Z"
                              },
                              {
                                "email": "new.user3@example.com",
                                "roles": ["USER"],
                                "createdAt": "2026-02-14T11:00:00Z"
                              }
                            ]
                          }
                        }
                        """
                            )
                    )
            )
    })
    public Mono<ResponseEntity<Map<String, Object>>> getApprovalStats() {
        Instant requestTime = clock.instant();

        log.debug("Fetching approval stats at {}", requestTime);

        return firebaseServiceAuth.findAllUsersByStatus(UserStatus.PENDING_APPROVAL)
                .collectList()
                .zipWith(firebaseServiceAuth.findAllUsersByStatus(UserStatus.ACTIVE).count())
                .map(tuple -> {
                    var pendingUsers = tuple.getT1();
                    var activeCount = tuple.getT2();

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "data", Map.of(
                                    "pendingCount", pendingUsers.size(),
                                    "activeCount", activeCount,
                                    "timestamp", requestTime.toString(),
                                    "pendingUsers", pendingUsers.stream()
                                            .map(user -> Map.of(
                                                    "email", user.getEmail(),
                                                    "roles", user.getRoles(),
                                                    "createdAt", user.getCreatedAt() != null ?
                                                            user.getCreatedAt().toString() :
                                                            requestTime.toString()
                                            ))
                                            .collect(Collectors.toList())
                            )
                    ));
                });
    }
}