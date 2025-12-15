package com.techStack.authSys.controller;

import com.techStack.authSys.service.bootstrap.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

/**
 * Diagnostic and management endpoints for bootstrap operations.
 * SECURITY: No password storage or retrieval endpoints.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/bootstrap")
@RequiredArgsConstructor
public class BootstrapDiagnosticController {

    private final BootstrapLockService lockService;
    private final BootstrapStateService stateService;
    private final BootstrapMonitoringService monitoringService;
    private final TransactionalBootstrapService transactionalBootstrapService;
    private final BootstrapNotificationService notificationService;

    /**
     * Gets current bootstrap status and health.
     */
    @GetMapping("/status")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getBootstrapStatus() {
        return Mono.zip(
                stateService.isBootstrapCompleted(),
                lockService.getLockStatus(),
                monitoringService.getBootstrapHealth()
        ).map(tuple -> {
            Map<String, Object> status = new HashMap<>();
            status.put("bootstrapComplete", tuple.getT1());
            status.put("lockStatus", tuple.getT2().toString());
            status.put("health", tuple.getT3());
            return ResponseEntity.ok(status);
        });
    }

    /**
     * Gets email delivery failures (for diagnostics).
     * Does NOT include passwords - only failure information.
     */
    @GetMapping("/email-failures")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<?>> getEmailFailures() {
        return monitoringService.getEmailFailures()
                .map(ResponseEntity::ok);
    }

    /**
     * Resends welcome email using Firebase password reset.
     * SECURE: Uses Firebase's built-in password reset, no password storage.
     */
    @PostMapping("/email/resend")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> resendWelcomeEmail(
            @RequestParam String email) {

        log.warn("🚨 ADMIN resending credentials via Firebase password reset: {}", maskEmail(email));

        return notificationService.sendPasswordResetLink(email)
                .then(Mono.fromCallable(() -> {
                    Map<String, String> response = new HashMap<>();
                    response.put("status", "success");
                    response.put("message", "Password reset link sent to email");
                    response.put("action", "Check email for reset link from Firebase");
                    return ResponseEntity.ok(response);
                }))
                .onErrorResume(e -> {
                    Map<String, String> response = new HashMap<>();
                    response.put("status", "error");
                    response.put("message", "Failed to send reset link: " + e.getMessage());
                    return Mono.just(ResponseEntity.status(500).body(response));
                });
    }

    /**
     * Forces release of the bootstrap lock.
     */
    @PostMapping("/lock/force-release")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> forceReleaseLock() {
        log.warn("⚠️ ADMIN requested forced lock release");

        return lockService.forceReleaseLock()
                .then(lockService.getLockStatus())
                .map(status -> {
                    Map<String, String> response = new HashMap<>();
                    response.put("message", "Lock forcefully released");
                    response.put("lockStatus", status.toString());
                    return ResponseEntity.ok(response);
                });
    }

    /**
     * Triggers a manual bootstrap attempt.
     */
    @PostMapping("/trigger")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> triggerBootstrap(
            @RequestParam String email,
            @RequestParam String phone) {

        log.warn("⚠️ ADMIN requested manual bootstrap trigger");

        return stateService.isBootstrapCompleted()
                .flatMap(isComplete -> {
                    if (isComplete) {
                        Map<String, String> response = new HashMap<>();
                        response.put("status", "error");
                        response.put("message", "Bootstrap already completed");
                        return Mono.just(ResponseEntity.badRequest().body(response));
                    }

                    return transactionalBootstrapService
                            .createSuperAdminTransactionally(email, phone)
                            .then(Mono.fromCallable(() -> {
                                Map<String, String> response = new HashMap<>();
                                response.put("status", "success");
                                response.put("message", "Bootstrap triggered - check logs if email fails");
                                return ResponseEntity.ok(response);
                            }))
                            .onErrorResume(e -> {
                                Map<String, String> response = new HashMap<>();
                                response.put("status", "error");
                                response.put("message", "Bootstrap failed: " + e.getMessage());
                                return Mono.just(ResponseEntity.status(500).body(response));
                            });
                });
    }

    /**
     * Resets bootstrap state (clears completion flag).
     */
    @DeleteMapping("/reset")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> resetBootstrap() {
        log.error("🚨 ADMIN requested bootstrap reset");

        return lockService.forceReleaseLock()
                .then(stateService.resetBootstrapState())
                .then(Mono.fromCallable(() -> {
                    Map<String, String> response = new HashMap<>();
                    response.put("status", "success");
                    response.put("message", "Bootstrap state reset");
                    return ResponseEntity.ok(response);
                }));
    }

    /**
     * Gets critical failures requiring manual intervention.
     */
    @GetMapping("/failures/critical")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<?>> getCriticalFailures() {
        return monitoringService.getCriticalFailures()
                .map(ResponseEntity::ok);
    }

    /**
     * Gets recent rollback events.
     */
    @GetMapping("/rollbacks")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<?>> getRecentRollbacks(
            @RequestParam(defaultValue = "24") int hours) {
        return monitoringService.getRecentRollbacks(hours)
                .map(ResponseEntity::ok);
    }

    /**
     * Marks a critical failure as resolved.
     */
    @PutMapping("/failures/{failureId}/resolve")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<Map<String, String>>> resolveFailure(
            @PathVariable String failureId,
            @RequestParam String resolution) {

        return monitoringService.markCriticalFailureResolved(failureId, resolution)
                .then(Mono.fromCallable(() -> {
                    Map<String, String> response = new HashMap<>();
                    response.put("status", "success");
                    response.put("message", "Failure marked as resolved");
                    return ResponseEntity.ok(response);
                }));
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        String[] parts = email.split("@");
        return parts[0].substring(0, Math.min(3, parts[0].length())) + "***@" + parts[1];
    }
}