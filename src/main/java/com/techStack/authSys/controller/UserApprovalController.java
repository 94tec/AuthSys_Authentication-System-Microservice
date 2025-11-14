package com.techStack.authSys.controller;

import com.techStack.authSys.dto.PendingUserResponse;
import com.techStack.authSys.dto.RequesterContext;
import com.techStack.authSys.dto.SecurityContext;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.security.SecurityContextService;
import com.techStack.authSys.service.AdminManagementService;
import com.techStack.authSys.service.FirebaseServiceAuth;
import com.techStack.authSys.service.RoleAssignmentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/users")
public class UserApprovalController {
    private static final Logger logger = LoggerFactory.getLogger(UserApprovalController.class);

    private final RoleAssignmentService roleAssignmentService;
    private final AdminManagementService adminManagementService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final SecurityContextService securityContextService;

    public UserApprovalController(RoleAssignmentService roleAssignmentService, AdminManagementService adminManagementService,
                                  FirebaseServiceAuth firebaseServiceAuth, SecurityContextService securityContextService) {
        this.roleAssignmentService = roleAssignmentService;
        this.adminManagementService = adminManagementService;
        this.firebaseServiceAuth = firebaseServiceAuth;

        this.securityContextService = securityContextService;
    }

    /**
     * Get pending users with comprehensive approval context
     */
    public Flux<PendingUserResponse> getPendingUsersWithApprovalContext(SecurityContext securityContext) {
        logger.info("📋 Fetching pending users with context - Requester: {} ({})",
                securityContext.getRequesterEmail(), securityContext.getRequesterRole());

        return firebaseServiceAuth.findAllUsersByStatus(User.Status.PENDING_APPROVAL)
                .map(user -> buildPendingUserResponse(user, securityContext))
                .doOnNext(response ->
                        logger.debug("👤 Pending user processed: {} | Can Approve: {}",
                                response.getEmail(), response.isCanApprove()));
    }

    private PendingUserResponse buildPendingUserResponse(User user, SecurityContext securityContext) {
        return PendingUserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(user.getRoles())
                .status(user.getStatus())
                .approvalLevel(getSafeApprovalLevel(user))
                .createdAt(getSafeCreatedAt(user))
                .department(getSafeDepartment(user))
                .canApprove(roleAssignmentService.canApproveUser(securityContext, user))
                .requesterContext(buildRequesterContext(securityContext))
                .build();
    }

    private RoleAssignmentService.ApprovalLevel getSafeApprovalLevel(User user) {
        return user.getApprovalLevel().orElse(RoleAssignmentService.ApprovalLevel.MANAGER_OR_ABOVE);
    }

    private Instant getSafeCreatedAt(User user) {
        return user.getCreatedAt() != null ? user.getCreatedAt() : Instant.now();
    }

    private String getSafeDepartment(User user) {
        return user.getDepartment() != null ? user.getDepartment() : "";
    }

    private RequesterContext buildRequesterContext(SecurityContext securityContext) {
        return RequesterContext.builder()
                .requesterEmail(securityContext.getRequesterEmail())
                .requesterRole(securityContext.getRequesterRole())
                .timestamp(Instant.now())
                .build();
    }

    /**
     * Approve a pending user
     * Enhanced with hierarchical authority validation
     */
    @PostMapping("/{userId}/approve")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Mono<ResponseEntity<Map<String, Object>>> approveUser(
            @PathVariable String userId,
            Authentication authentication) {

        String approverEmail = authentication.getName();
        Roles approverRole = roleAssignmentService.extractHighestRole(authentication);

        logger.info("👤 Approval request for user {} by {} ({})", userId, approverEmail, approverRole);

        return adminManagementService.approveUserAccount(userId, approverEmail, approverRole)
                .map(user -> {
                    logger.info("✅ User {} approved successfully by {}", user.getEmail(), approverEmail);
                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "User approved successfully",
                            "data", Map.of(
                                    "userId", user.getId(),
                                    "email", user.getEmail(),
                                    "status", user.getStatus().name(),
                                    "enabled", user.isEnabled(),
                                    "roles", user.getRoles(),
                                    "permissions", user.getPermissions() != null ? user.getPermissions() : List.of(),
                                    "approvedBy", approverEmail,
                                    "approvedAt", user.getApprovedAt() != null ? user.getApprovedAt().toString() : ""
                            )
                    ));
                })
                .onErrorResume(SecurityException.class, e -> {
                    logger.warn("🚫 Insufficient authority: {} cannot approve user {} - {}",
                            approverRole, userId, e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of(
                                    "success", false,
                                    "message", "Insufficient authority to approve this user",
                                    "details", e.getMessage()
                            )));
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    logger.warn("⚠️ Cannot approve user {}: {}", userId, e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Map.of(
                                    "success", false,
                                    "message", e.getMessage()
                            )));
                })
                .onErrorResume(e -> {
                    logger.error("❌ Error approving user {}: {}", userId, e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of(
                                    "success", false,
                                    "message", "Failed to approve user: " + e.getMessage()
                            )));
                });
    }

    /**
     * Reject a pending user
     * Enhanced with reason tracking per document recommendation
     */
    @PostMapping("/{userId}/reject")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Mono<ResponseEntity<Map<String, Object>>> rejectUser(
            @PathVariable String userId,
            @RequestBody Map<String, String> request,
            Authentication authentication) {

        String rejectorEmail = authentication.getName();
        Roles rejectorRole = roleAssignmentService.extractHighestRole(authentication);
        String reason = request.getOrDefault("reason", "No reason provided");

        logger.info("❌ Rejection request for user {} by {} ({}) - Reason: {}",
                userId, rejectorEmail, rejectorRole, reason);

        return adminManagementService.rejectUserAccount(userId, rejectorEmail, rejectorRole, reason)
                .then(Mono.just(ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "User rejected and removed from system",
                        "data", Map.of(
                                "userId", userId,
                                "rejectedBy", rejectorEmail,
                                "reason", reason
                        )
                ))))
                .onErrorResume(SecurityException.class, e -> {
                    logger.warn("🚫 Insufficient authority: {} cannot reject user {} - {}",
                            rejectorRole, userId, e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of(
                                    "success", false,
                                    "message", "Insufficient authority to reject this user",
                                    "details", e.getMessage()
                            )));
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    logger.warn("⚠️ Cannot reject user {}: {}", userId, e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Map.of(
                                    "success", false,
                                    "message", e.getMessage()
                            )));
                })
                .onErrorResume(e -> {
                    logger.error("❌ Error rejecting user {}: {}", userId, e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of(
                                    "success", false,
                                    "message", "Failed to reject user: " + e.getMessage()
                            )));
                });
    }

    /**
     * Get user details by ID
     */
    @GetMapping("/{userId}")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Mono<ResponseEntity<Map<String, Object>>> getUserById(
            @PathVariable String userId,
            Authentication authentication) {

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
                                            Map.entry("approvalLevel", user.getApprovalLevel() != null ? user.getApprovalLevel() : ""),
                                            Map.entry("createdAt", user.getCreatedAt() != null ? user.getCreatedAt().toString() : ""),
                                            Map.entry("approvedAt", user.getApprovedAt() != null ? user.getApprovedAt().toString() : ""),
                                            Map.entry("approvedBy", user.getApprovedBy() != null ? user.getApprovedBy() : ""),
                                            Map.entry("department", user.getDepartment() != null ? user.getDepartment() : ""),
                                            Map.entry("canApprove",
                                                    roleAssignmentService.canApproveUser(securityContext, user))
                                    );

                                    return ResponseEntity.ok(
                                            Map.of(
                                                    "success", true,
                                                    "data", data
                                            )
                                    );
                                })
                )
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    /**
     * Get all users with optional status filter
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Flux<Map<String, Object>> getAllUsers(
            @RequestParam(required = false) String status,
            Authentication authentication) {

        Roles approverRole = roleAssignmentService.extractHighestRole(authentication);

        Flux<User> userFlux;
        if (status != null) {
            try {
                User.Status userStatus = User.Status.valueOf(status.toUpperCase());
                userFlux = firebaseServiceAuth.findAllUsersByStatus(userStatus);
            } catch (IllegalArgumentException e) {
                logger.warn("⚠️ Invalid status filter: {}", status);
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
                "createdAt", user.getCreatedAt() != null ? user.getCreatedAt().toString() : ""
                //"canApprove", roleAssignmentService.canApproveUser(SecurityContext securityContext, User targetUser))
        ));
    }

    /**
     * Get approval statistics
     */
    @GetMapping("/stats")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Mono<ResponseEntity<Map<String, Object>>> getApprovalStats() {
        return firebaseServiceAuth.findAllUsersByStatus(User.Status.PENDING_APPROVAL)
                .collectList()
                .zipWith(firebaseServiceAuth.findAllUsersByStatus(User.Status.ACTIVE).count())
                .map(tuple -> {
                    var pendingUsers = tuple.getT1();
                    var activeCount = tuple.getT2();

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "data", Map.of(
                                    "pendingCount", pendingUsers.size(),
                                    "activeCount", activeCount,
                                    "pendingUsers", pendingUsers.stream()
                                            .map(user -> Map.of(
                                                    "email", user.getEmail(),
                                                    "roles", user.getRoles(),
                                                    "createdAt", user.getCreatedAt() != null ?
                                                            user.getCreatedAt().toString() : ""
                                            ))
                                            .collect(Collectors.toList())
                            )
                    ));
                });
    }

}

