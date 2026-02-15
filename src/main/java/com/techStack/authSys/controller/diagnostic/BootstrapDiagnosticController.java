package com.techStack.authSys.controller.diagnostic;

import com.techStack.authSys.service.bootstrap.*;
import com.techStack.authSys.util.validation.HelperUtils;
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
import java.util.HashMap;
import java.util.Map;

/**
 * Bootstrap Diagnostic Controller
 *
 * Diagnostic and management endpoints for bootstrap operations.
 * SECURITY: No password storage or retrieval endpoints.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/bootstrap")
@RequiredArgsConstructor
@Tag(
        name = "Bootstrap Diagnostics",
        description = """
                Bootstrap system diagnostics and management.
                
                **Purpose:**
                - Monitor bootstrap health and status
                - Manage bootstrap locks and failures
                - Trigger manual bootstrap operations
                - Handle email delivery issues
                
                **Security:**
                - All endpoints require SUPER_ADMIN or ADMIN role
                - No password storage or retrieval
                - Audit logging for all operations
                - Uses Firebase password reset for credential recovery
                
                **Use Cases:**
                - Check if bootstrap completed successfully
                - Resend welcome emails using Firebase password reset
                - Force release stuck locks
                - Reset bootstrap state for re-initialization
                - Monitor and resolve critical failures
                
                **⚠️ CAUTION:**
                These are administrative operations that can affect system initialization.
                Use with care and only when necessary.
                """
)
public class BootstrapDiagnosticController {

    /* =========================
       Dependencies
       ========================= */

    private final BootstrapLockService lockService;
    private final BootstrapStateService stateService;
    private final BootstrapMonitoringService monitoringService;
    private final TransactionalBootstrapService transactionalBootstrapService;
    private final BootstrapNotificationService notificationService;
    private final Clock clock;

    /* =========================
       Status & Health
       ========================= */

    @Operation(
            summary = "Get Bootstrap Status",
            description = """
                    Get current bootstrap system status and health.
                    
                    **Returns:**
                    - Bootstrap completion status
                    - Lock status (AVAILABLE, ACQUIRED, EXPIRED)
                    - System health metrics
                    - Timestamp of check
                    
                    **Health Metrics Include:**
                    - Bootstrap attempts
                    - Success rate
                    - Email delivery status
                    - Lock status
                    - Last bootstrap timestamp
                    
                    **Use Cases:**
                    - Verify bootstrap completed successfully
                    - Check for stuck locks
                    - Monitor system initialization health
                    - Troubleshoot bootstrap issues
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Bootstrap status retrieved",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "bootstrapComplete": true,
                                              "lockStatus": "AVAILABLE",
                                              "health": {
                                                "totalAttempts": 1,
                                                "successfulAttempts": 1,
                                                "failedAttempts": 0,
                                                "emailDeliveryRate": 100.0,
                                                "lastBootstrapAt": "2024-03-15T10:30:00Z",
                                                "lockAcquisitions": 1,
                                                "lockReleases": 1
                                              },
                                              "checkedAt": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Not authenticated"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Insufficient permissions (requires ADMIN or SUPER_ADMIN)"
            )
    })
    @GetMapping("/status")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getBootstrapStatus() {
        Instant requestTime = clock.instant();

        log.info("Bootstrap status check at {}", requestTime);

        return Mono.zip(
                stateService.isBootstrapCompleted(),
                lockService.getLockStatus(),
                monitoringService.getBootstrapHealth()
        ).map(tuple -> {
            Map<String, Object> status = new HashMap<>();
            status.put("bootstrapComplete", tuple.getT1());
            status.put("lockStatus", tuple.getT2().toString());
            status.put("health", tuple.getT3());
            status.put("checkedAt", requestTime.toString());
            return ResponseEntity.ok(status);
        });
    }

    @Operation(
            summary = "Get Email Delivery Failures",
            description = """
                    Get list of failed email deliveries during bootstrap.
                    
                    **Security:**
                    - Does NOT include passwords or sensitive data
                    - Only shows delivery failure metadata
                    
                    **Returns:**
                    - Failed email attempts
                    - Error messages
                    - Timestamps
                    - Retry attempts
                    
                    **Use Cases:**
                    - Debug email delivery issues
                    - Identify SMTP configuration problems
                    - Monitor email service health
                    - Determine if manual intervention needed
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Email failures retrieved",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "data": [
                                                {
                                                  "email": "a****n@example.com",
                                                  "attemptedAt": "2024-03-15T10:30:00Z",
                                                  "errorMessage": "SMTP connection timeout",
                                                  "retryCount": 3,
                                                  "lastRetryAt": "2024-03-15T10:35:00Z"
                                                }
                                              ],
                                              "timestamp": "2024-03-15T14:22:30Z"
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
    @GetMapping("/email-failures")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getEmailFailures() {
        Instant requestTime = clock.instant();

        log.info("Fetching email failures at {}", requestTime);

        return monitoringService.getEmailFailures()
                .map(failures -> ResponseEntity.ok(Map.of(
                        "success", true,
                        "data", failures,
                        "timestamp", requestTime.toString()
                )));
    }

    /* =========================
       Email Operations
       ========================= */

    @Operation(
            summary = "Resend Welcome Email (Password Reset)",
            description = """
                    Resend credentials using Firebase password reset link.
                    
                    **Security:**
                    - Uses Firebase's built-in password reset mechanism
                    - No password storage or retrieval
                    - Password reset link expires in 1 hour
                    - Single use only
                    
                    **Process:**
                    1. Admin triggers password reset
                    2. Firebase sends reset link to user's email
                    3. User clicks link
                    4. User sets their own password
                    5. User can then login normally
                    
                    **Use Cases:**
                    - User didn't receive original email
                    - Original email expired or deleted
                    - Email delivery failed during bootstrap
                    - User forgot temporary password
                    
                    **⚠️ Important:**
                    This invalidates any previous password reset links.
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password reset link sent",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "status": "success",
                                              "message": "Password reset link sent to email",
                                              "action": "Check email for reset link from Firebase",
                                              "sentAt": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "User not found"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Failed to send reset link",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "status": "error",
                                              "message": "Failed to send reset link: SMTP connection failed",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/email/resend")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> resendWelcomeEmail(
            @Parameter(
                    description = "User email address",
                    required = true,
                    example = "admin@techstack.com"
            )
            @RequestParam String email) {

        Instant requestTime = clock.instant();

        log.warn("🚨 ADMIN resending credentials via Firebase password reset at {} for: {}",
                requestTime, HelperUtils.maskEmail(email));

        return notificationService.sendPasswordResetLink(email)
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    Map<String, String> response = new HashMap<>();
                    response.put("status", "success");
                    response.put("message", "Password reset link sent to email");
                    response.put("action", "Check email for reset link from Firebase");
                    response.put("sentAt", completionTime.toString());
                    return ResponseEntity.ok(response);
                }))
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("Failed to send reset link at {}: {}", errorTime, e.getMessage());

                    Map<String, String> response = new HashMap<>();
                    response.put("status", "error");
                    response.put("message", "Failed to send reset link: " + e.getMessage());
                    response.put("timestamp", errorTime.toString());
                    return Mono.just(ResponseEntity.status(500).body(response));
                });
    }

    /* =========================
       Lock Management
       ========================= */

    @Operation(
            summary = "Force Release Bootstrap Lock",
            description = """
                    Forcefully release the bootstrap lock.
                    
                    **⚠️ DANGER - Use with extreme caution!**
                    
                    **When to Use:**
                    - Bootstrap process crashed and left lock acquired
                    - Lock expired but wasn't released properly
                    - System stuck in "bootstrap in progress" state
                    - Manual intervention required to reset system
                    
                    **What This Does:**
                    - Immediately releases the bootstrap lock
                    - Allows new bootstrap attempts
                    - Does NOT roll back any partial changes
                    - Does NOT validate system state
                    
                    **Before Using:**
                    1. Verify no bootstrap process is actually running
                    2. Check logs for what caused the stuck lock
                    3. Consider if partial bootstrap data needs cleanup
                    4. Document the reason for forced release
                    
                    **After Using:**
                    - Verify lock status shows AVAILABLE
                    - Check bootstrap health metrics
                    - Consider triggering fresh bootstrap if needed
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Lock released successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "message": "Lock forcefully released",
                                              "lockStatus": "AVAILABLE",
                                              "releasedAt": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/lock/force-release")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> forceReleaseLock() {
        Instant releaseTime = clock.instant();

        log.warn("⚠️ ADMIN requested forced lock release at {}", releaseTime);

        return lockService.forceReleaseLock()
                .then(lockService.getLockStatus())
                .map(status -> {
                    Instant completionTime = clock.instant();

                    Map<String, String> response = new HashMap<>();
                    response.put("message", "Lock forcefully released");
                    response.put("lockStatus", status.toString());
                    response.put("releasedAt", completionTime.toString());
                    return ResponseEntity.ok(response);
                });
    }

    /* =========================
       Bootstrap Triggering
       ========================= */

    @Operation(
            summary = "Trigger Manual Bootstrap",
            description = """
                    Manually trigger bootstrap process for Super Admin creation.
                    
                    **Requirements:**
                    - Bootstrap must NOT already be completed
                    - Valid email and phone number
                    - No other bootstrap process running
                    
                    **Process:**
                    1. Validates bootstrap not already complete
                    2. Acquires bootstrap lock
                    3. Creates Super Admin account
                    4. Sends welcome email with credentials
                    5. Releases lock
                    6. Marks bootstrap as complete
                    
                    **Email Delivery:**
                    - Success: User receives Firebase password reset link
                    - Failure: Account created but email not sent
                    - Check logs for email failures
                    - Use /email/resend if delivery fails
                    
                    **Use Cases:**
                    - Initial system setup
                    - Re-create Super Admin after deletion
                    - Test bootstrap process in dev/staging
                    
                    **⚠️ Note:**
                    Can only be executed once unless bootstrap state is reset.
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Bootstrap triggered successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "status": "success",
                                              "message": "Bootstrap triggered - check logs if email fails",
                                              "triggeredAt": "2024-03-15T14:22:30Z",
                                              "completedAt": "2024-03-15T14:22:35Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Bootstrap already completed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "status": "error",
                                              "message": "Bootstrap already completed",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Bootstrap failed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "status": "error",
                                              "message": "Bootstrap failed: Database connection error",
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/trigger")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> triggerBootstrap(
            @Parameter(
                    description = "Super Admin email",
                    required = true,
                    example = "admin@techstack.com"
            )
            @RequestParam String email,

            @Parameter(
                    description = "Phone number in E.164 format",
                    required = true,
                    example = "+254712345678"
            )
            @RequestParam String phone) {

        Instant triggerTime = clock.instant();

        log.warn("⚠️ ADMIN requested manual bootstrap trigger at {} for: {}",
                triggerTime, HelperUtils.maskEmail(email));

        return stateService.isBootstrapCompleted()
                .flatMap(isComplete -> {
                    if (isComplete) {
                        Map<String, String> response = new HashMap<>();
                        response.put("status", "error");
                        response.put("message", "Bootstrap already completed");
                        response.put("timestamp", clock.instant().toString());
                        return Mono.just(ResponseEntity.badRequest().body(response));
                    }

                    return transactionalBootstrapService
                            .createSuperAdminTransactionally(email, phone)
                            .then(Mono.fromCallable(() -> {
                                Instant completionTime = clock.instant();

                                Map<String, String> response = new HashMap<>();
                                response.put("status", "success");
                                response.put("message", "Bootstrap triggered - check logs if email fails");
                                response.put("triggeredAt", triggerTime.toString());
                                response.put("completedAt", completionTime.toString());
                                return ResponseEntity.ok(response);
                            }))
                            .onErrorResume(e -> {
                                Instant errorTime = clock.instant();

                                log.error("Bootstrap trigger failed at {}: {}",
                                        errorTime, e.getMessage());

                                Map<String, String> response = new HashMap<>();
                                response.put("status", "error");
                                response.put("message", "Bootstrap failed: " + e.getMessage());
                                response.put("timestamp", errorTime.toString());
                                return Mono.just(ResponseEntity.status(500).body(response));
                            });
                });
    }

    /* =========================
       State Reset
       ========================= */

    @Operation(
            summary = "Reset Bootstrap State",
            description = """
                    Reset bootstrap completion state and release locks.
                    
                    **⚠️ EXTREME CAUTION - DESTRUCTIVE OPERATION**
                    
                    **What This Does:**
                    - Clears bootstrap completion flag
                    - Releases all bootstrap locks
                    - Allows bootstrap to run again
                    - Does NOT delete existing Super Admin
                    - Does NOT roll back any data
                    
                    **When to Use:**
                    - Need to re-run bootstrap process
                    - Testing bootstrap in dev/staging
                    - Recovering from partial bootstrap
                    - System migration or restoration
                    
                    **⚠️ WILL NOT:**
                    - Delete existing Super Admin account
                    - Remove any created users
                    - Clear audit logs
                    - Restore system to pre-bootstrap state
                    
                    **Before Using:**
                    1. Document why reset is needed
                    2. Backup current system state
                    3. Verify existing Super Admin can still login
                    4. Check for any dependent processes
                    5. Get approval from system owner
                    
                    **After Using:**
                    - Verify bootstrap state shows incomplete
                    - Check lock status shows AVAILABLE
                    - Test bootstrap trigger if needed
                    - Monitor for any system issues
                    
                    **Production Warning:**
                    This should NEVER be used in production unless
                    absolutely necessary and with full understanding
                    of the implications.
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Bootstrap state reset",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "status": "success",
                                              "message": "Bootstrap state reset",
                                              "resetAt": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @DeleteMapping("/reset")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> resetBootstrap() {
        Instant resetTime = clock.instant();

        log.error("🚨 ADMIN requested bootstrap reset at {}", resetTime);

        return lockService.forceReleaseLock()
                .then(stateService.resetBootstrapState())
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    Map<String, String> response = new HashMap<>();
                    response.put("status", "success");
                    response.put("message", "Bootstrap state reset");
                    response.put("resetAt", completionTime.toString());
                    return ResponseEntity.ok(response);
                }));
    }

    /* =========================
       Failure Management
       ========================= */

    @Operation(
            summary = "Get Critical Failures",
            description = """
                    Get list of critical failures requiring manual intervention.
                    
                    **Returns:**
                    - Bootstrap failures
                    - Email delivery failures
                    - Lock acquisition failures
                    - Transaction rollback events
                    - System errors during bootstrap
                    
                    **Failure Severity:**
                    - CRITICAL: Requires immediate attention
                    - HIGH: Should be addressed soon
                    - MEDIUM: Monitor for patterns
                    - LOW: Informational
                    
                    **Use Cases:**
                    - Monitor bootstrap health
                    - Identify recurring issues
                    - Plan manual interventions
                    - Generate failure reports
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Critical failures retrieved"
            )
    })
    @GetMapping("/failures/critical")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getCriticalFailures() {
        Instant requestTime = clock.instant();

        log.info("Fetching critical failures at {}", requestTime);

        return monitoringService.getCriticalFailures()
                .map(failures -> ResponseEntity.ok(Map.of(
                        "success", true,
                        "data", failures,
                        "timestamp", requestTime.toString()
                )));
    }

    @Operation(
            summary = "Get Recent Rollbacks",
            description = """
                    Get recent transaction rollback events.
                    
                    **Returns:**
                    - Rollback timestamp
                    - Reason for rollback
                    - Operation that was rolled back
                    - Error details
                    - Cleanup actions taken
                    
                    **Use Cases:**
                    - Monitor system stability
                    - Identify patterns in failures
                    - Verify rollback mechanisms working
                    - Debug bootstrap issues
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Rollback events retrieved"
            )
    })
    @GetMapping("/rollbacks")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getRecentRollbacks(
            @Parameter(
                    description = "Number of hours to look back",
                    example = "24"
            )
            @RequestParam(defaultValue = "24") int hours) {

        Instant requestTime = clock.instant();

        log.info("Fetching rollbacks from last {} hours at {}", hours, requestTime);

        return monitoringService.getRecentRollbacks(hours)
                .map(rollbacks -> ResponseEntity.ok(Map.of(
                        "success", true,
                        "data", rollbacks,
                        "hours", hours,
                        "timestamp", requestTime.toString()
                )));
    }

    @Operation(
            summary = "Mark Failure as Resolved",
            description = """
                    Mark a critical failure as resolved with resolution notes.
                    
                    **Process:**
                    1. Admin investigates failure
                    2. Takes corrective action
                    3. Documents resolution
                    4. Marks failure as resolved
                    
                    **Resolution Notes Should Include:**
                    - What caused the failure
                    - What action was taken
                    - Whether issue is permanently fixed
                    - Any follow-up actions needed
                    
                    **Use Cases:**
                    - Track failure resolution
                    - Document system maintenance
                    - Clear resolved issues from critical list
                    - Maintain audit trail
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Failure marked as resolved",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "status": "success",
                                              "message": "Failure marked as resolved",
                                              "failureId": "failure-123",
                                              "resolution": "Fixed SMTP configuration and resent email successfully",
                                              "resolvedAt": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            )
    })
    @PutMapping("/failures/{failureId}/resolve")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> resolveFailure(
            @Parameter(
                    description = "Failure ID to resolve",
                    required = true,
                    example = "failure-123"
            )
            @PathVariable String failureId,

            @Parameter(
                    description = "Resolution description",
                    required = true,
                    example = "Fixed SMTP configuration and resent email"
            )
            @RequestParam String resolution) {

        Instant resolveTime = clock.instant();

        log.info("Resolving failure {} at {}: {}", failureId, resolveTime, resolution);

        return monitoringService.markCriticalFailureResolved(failureId, resolution)
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    Map<String, String> response = new HashMap<>();
                    response.put("status", "success");
                    response.put("message", "Failure marked as resolved");
                    response.put("failureId", failureId);
                    response.put("resolution", resolution);
                    response.put("resolvedAt", completionTime.toString());
                    return ResponseEntity.ok(response);
                }));
    }
}