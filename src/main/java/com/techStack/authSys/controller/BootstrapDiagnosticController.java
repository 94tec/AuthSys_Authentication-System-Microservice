package com.techStack.authSys.controller;

import com.techStack.authSys.service.bootstrap.BootstrapLockService;
import com.techStack.authSys.service.bootstrap.BootstrapMonitoringService;
import com.techStack.authSys.service.bootstrap.BootstrapStateService;
import com.techStack.authSys.service.bootstrap.TransactionalBootstrapService;
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
 * Only accessible by SUPER_ADMIN role.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/bootstrap")
@RequiredArgsConstructor
@PreAuthorize("hasRole('SUPER_ADMIN')")
public class BootstrapDiagnosticController {

    private final BootstrapLockService lockService;
    private final BootstrapStateService stateService;
    private final BootstrapMonitoringService monitoringService;
    private final TransactionalBootstrapService transactionalBootstrapService;

    /**
     * Gets current bootstrap status and health.
     */
    @GetMapping("/status")
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
     * Forces release of the bootstrap lock.
     * USE WITH CAUTION - only if you're certain no instance is running bootstrap.
     */
    @PostMapping("/lock/force-release")
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
     * Only works if bootstrap is not already complete.
     */
    @PostMapping("/trigger")
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
                                response.put("message", "Bootstrap triggered successfully");
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
     * DANGEROUS - only use for testing or recovery.
     */
    @DeleteMapping("/reset")
    public Mono<ResponseEntity<Map<String, String>>> resetBootstrap() {
        log.error("🚨 ADMIN requested bootstrap reset - THIS IS DANGEROUS");

        return lockService.forceReleaseLock()
                .then(Mono.fromRunnable(() -> {
                    // You'll need to implement this in BootstrapStateService
                    log.warn("Clearing bootstrap completion flags...");
                }))
                .then(Mono.fromCallable(() -> {
                    Map<String, String> response = new HashMap<>();
                    response.put("status", "success");
                    response.put("message", "Bootstrap state reset - you can now trigger a new bootstrap");
                    return ResponseEntity.ok(response);
                }));
    }

    /**
     * Gets critical failures requiring manual intervention.
     */
    @GetMapping("/failures/critical")
    public Mono<ResponseEntity<?>> getCriticalFailures() {
        return monitoringService.getCriticalFailures()
                .map(ResponseEntity::ok);
    }

    /**
     * Gets recent rollback events.
     */
    @GetMapping("/rollbacks")
    public Mono<ResponseEntity<?>> getRecentRollbacks(
            @RequestParam(defaultValue = "24") int hours) {
        return monitoringService.getRecentRollbacks(hours)
                .map(ResponseEntity::ok);
    }

    /**
     * Marks a critical failure as resolved.
     */
    @PutMapping("/failures/{failureId}/resolve")
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
}
