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
import com.techStack.authSys.service.user.AdminManagementService;
import com.techStack.authSys.service.user.UserApprovalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
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
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
public class UserApprovalController {

    /* =========================
       Dependencies
       ========================= */

    private final RoleAssignmentService roleAssignmentService;
    //private final AdminManagementService adminManagementService;
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
    @GetMapping("/pending")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Flux<PendingUserResponse> getPendingUsersWithApprovalContext(Authentication authentication) {
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
    @PostMapping("/{userId}/approve")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Mono<ResponseEntity<Map<String, Object>>> approveUser(
            @PathVariable String userId,
            Authentication authentication) {

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
    @PostMapping("/{userId}/reject")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Mono<ResponseEntity<Map<String, Object>>> rejectUser(
            @PathVariable String userId,
            @RequestBody Map<String, String> request,
            Authentication authentication) {

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
    @GetMapping("/{userId}")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Mono<ResponseEntity<Map<String, Object>>> getUserById(
            @PathVariable String userId,
            Authentication authentication) {

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
    @GetMapping
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
    public Flux<Map<String, Object>> getAllUsers(
            @RequestParam(required = false) String status,
            Authentication authentication) {

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
    @GetMapping("/stats")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'MANAGER')")
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