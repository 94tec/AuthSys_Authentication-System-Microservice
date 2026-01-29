package com.techStack.authSys.controller.audit;

import com.techStack.authSys.dto.response.AuditLogDTO;
import com.techStack.authSys.dto.response.UserPermissionsDTO;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.audit.AuditEventLog;
import com.techStack.authSys.repository.authorization.PermissionProvider;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/audit-logs")
public class AuditLogController {
    private final AuditLogService auditLogService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PermissionProvider permissionProvider;

    public AuditLogController(AuditLogService auditLogService, FirebaseServiceAuth firebaseServiceAuth, PermissionProvider permissionProvider) {
        this.auditLogService = auditLogService;
        this.firebaseServiceAuth = firebaseServiceAuth;
        this.permissionProvider = permissionProvider;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<List<AuditLogDTO>> getAuditLogs() {
        return ResponseEntity.ok(auditLogService.getAuditLogs());
    }

    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.uid")
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<AuditLogDTO>> getAuditLogsByUser(@PathVariable String userId) {
        return ResponseEntity.ok(auditLogService.getAuditLogsByUser(userId));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/action/{actionType}")
    public ResponseEntity<List<AuditLogDTO>> getAuditLogsByAction(@PathVariable ActionType actionType) {
        return ResponseEntity.ok(auditLogService.getAuditLogsByAction(actionType));
    }
    @GetMapping("/users/{userId}/permissions")
    public Mono<UserPermissionsDTO> getUserPermissions(@PathVariable String userId,
                                                       @RequestHeader("X-Admin-Id") String adminId) {
        return firebaseServiceAuth.getUserById(userId)
                .flatMap(user -> {
                    List<String> permissions = permissionProvider.resolveEffectivePermissions(user).stream().toList();
                    List<String> roles = user.getRoleNames();

                    // Audit
                    AuditEventLog event = new AuditEventLog();
                    event.setAction("PERMISSION_CHECK");
                    event.setPerformedBy(adminId);
                    event.setTargetUser(userId);
                    event.setTimestamp(Instant.now());
                    event.setMetadata(Map.of("roles", roles, "checkedPermissions", permissions));

                    return auditLogService.logEventLog(event)
                            .thenReturn(new UserPermissionsDTO(userId, roles, permissions));
                });
    }

}
