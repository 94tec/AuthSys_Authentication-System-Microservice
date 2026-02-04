package com.techStack.authSys.controller.audit;

import com.techStack.authSys.dto.response.AuditLogDTO;
import com.techStack.authSys.dto.response.UserPermissionsDTO;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.audit.AuditEventLog;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.observability.AuditLogService;
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

    /**
     * Get all audit logs
     */
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

    /**
     * Get audit logs by user
     */
    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.uid")
    public ResponseEntity<Map<String, Object>> getAuditLogsByUser(@PathVariable String userId) {
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

    /**
     * Get audit logs by action type
     */
    @GetMapping("/action/{actionType}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAuditLogsByAction(@PathVariable ActionType actionType) {
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

    /**
     * Get user permissions with audit logging
     */
    @GetMapping("/users/{userId}/permissions")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<ResponseEntity<Map<String, Object>>> getUserPermissions(
            @PathVariable String userId,
            @RequestHeader("X-Admin-Id") String adminId) {

        Instant checkTime = clock.instant();

        log.info("Permission check at {} for user {} by admin {}", checkTime, userId, adminId);

        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    List<String> permissions = permissionProvider.resolveEffectivePermissions(user)
                            .stream()
                            .map(Enum::name)
                            .toList();
                    List<String> roles = user.getRoleNames();

                    // Create audit event
                    AuditEventLog event = new AuditEventLog();
                    event.setAction("PERMISSION_CHECK");
                    event.setPerformedBy(adminId);
                    event.setTargetUser(userId);
                    event.setTimestamp(checkTime);
                    event.setMetadata(Map.of(
                            "roles", roles,
                            "checkedPermissions", permissions
                    ));

                    // Log audit event
                    return auditLogService.logEventLog(event)
                            .thenReturn(new UserPermissionsDTO(userId, roles, permissions))
                            .map(dto -> ResponseEntity.ok(Map.of(
                                    "success", true,
                                    "data", dto,
                                    "checkedAt", checkTime.toString(),
                                    "checkedBy", adminId
                            )));
                });
    }
}