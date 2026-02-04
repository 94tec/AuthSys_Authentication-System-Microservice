package com.techStack.authSys.controller.diagnostic;

import com.techStack.authSys.service.bootstrap.*;
import com.techStack.authSys.util.validation.HelperUtils;
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

    /**
     * Get current bootstrap status and health
     */
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

    /**
     * Get email delivery failures (for diagnostics only - NO passwords)
     */
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

    /**
     * Resend welcome email using Firebase password reset
     * SECURE: Uses Firebase's built-in password reset, no password storage
     */
    @PostMapping("/email/resend")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> resendWelcomeEmail(
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

    /**
     * Force release of the bootstrap lock
     */
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

    /**
     * Trigger a manual bootstrap attempt
     */
    @PostMapping("/trigger")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> triggerBootstrap(
            @RequestParam String email,
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

    /**
     * Reset bootstrap state (clears completion flag)
     */
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

    /**
     * Get critical failures requiring manual intervention
     */
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

    /**
     * Get recent rollback events
     */
    @GetMapping("/rollbacks")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getRecentRollbacks(
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

    /**
     * Mark a critical failure as resolved
     */
    @PutMapping("/failures/{failureId}/resolve")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> resolveFailure(
            @PathVariable String failureId,
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