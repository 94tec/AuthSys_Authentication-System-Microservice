package com.techStack.authSys.service.observability;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.techStack.authSys.dto.response.AuditLogDTO;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.audit.AuditEventLog;
import com.techStack.authSys.models.audit.AuditLogEntryPasswordChange;
import com.techStack.authSys.models.session.DeviceInfo;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.security.context.CurrentUserProvider;
import com.techStack.authSys.util.firebase.FirestoreUtils;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import static com.techStack.authSys.constants.SecurityConstants.*;

/**
 * Audit Log Service
 *
 * Centralized audit logging with Clock-based timestamps.
 * Provides comprehensive audit trail for all system operations.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    /* =========================
       Dependencies
       ========================= */

    private final Firestore firestore;
    private final Clock clock;
    private final CurrentUserProvider currentUserProvider;

    /* =========================
       Bootstrap Audit Logs
       ========================= */

    /**
     * Log transaction failure with rollback details
     */
    public void logTransactionFailure(
            String operation,
            String userId,
            String error,
            Map<String, Object> context) {

        Instant now = clock.instant();

        Map<String, Object> auditData = new HashMap<>();
        auditData.put("timestamp", now.toString());
        auditData.put("timestampMillis", now.toEpochMilli());
        auditData.put("operation", operation);
        auditData.put("userId", userId);
        auditData.put("status", "ROLLBACK_TRIGGERED");
        auditData.put("error", error);
        auditData.put("context", context);
        auditData.put("severity", "CRITICAL");

        try {
            firestore.collection(AUDIT_ROLLBACKS_COLLECTION)
                    .document(UUID.randomUUID().toString())
                    .set(auditData)
                    .get();

            log.warn("📋 Critical rollback logged at {} for operation: {}", now, operation);
        } catch (Exception e) {
            log.error("❌ Failed to log rollback at {}: {}", now, e.getMessage());
        }
    }

    /**
     * Log partial save scenarios requiring manual cleanup
     */
    public void logPartialSave(
            String userId,
            Map<String, String> savedCollections,
            String failedCollection) {

        Instant now = clock.instant();

        Map<String, Object> partialSaveData = new HashMap<>();
        partialSaveData.put("timestamp", now.toString());
        partialSaveData.put("timestampMillis", now.toEpochMilli());
        partialSaveData.put("userId", userId);
        partialSaveData.put("savedCollections", savedCollections);
        partialSaveData.put("failedCollection", failedCollection);
        partialSaveData.put("action", "REQUIRES_MANUAL_CLEANUP");
        partialSaveData.put("severity", "HIGH");

        try {
            firestore.collection(AUDIT_PARTIAL_SAVES_COLLECTION)
                    .document(UUID.randomUUID().toString())
                    .set(partialSaveData)
                    .get();

            log.warn("⚠️ Partial save logged at {} - manual cleanup required", now);
        } catch (Exception e) {
            log.error("❌ Failed to log partial save at {}: {}", now, e.getMessage());
        }
    }

    /**
     * Log successful bootstrap completion
     */
    public Mono<Void> logBootstrapSuccess(String email, long durationMs) {
        Instant now = clock.instant();

        Map<String, Object> auditData = Map.of(
                "timestamp", now.toString(),
                "timestampMillis", now.toEpochMilli(),
                "operation", "SUPER_ADMIN_BOOTSTRAP",
                "status", "SUCCESS",
                "email", HelperUtils.maskEmail(email),
                "durationMs", durationMs
        );

        return Mono.fromRunnable(() -> {
            try {
                firestore.collection(AUDIT_BOOTSTRAP_COLLECTION)
                        .document(UUID.randomUUID().toString())
                        .set(auditData)
                        .get();

                log.info("✅ Bootstrap success logged at {} for: {}",
                        now, HelperUtils.maskEmail(email));
            } catch (Exception e) {
                log.error("Failed to log bootstrap success at {}: {}", now, e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /* =========================
       Standard Audit Logs
       ========================= */

    /**
     * Log audit event
     */
    public Mono<Void> logEventLog(AuditEventLog event) {
        Instant now = clock.instant();

        // Ensure event has timestamp
        if (event.getTimestamp() == null) {
            event.setTimestamp(now);
        }

        try {
            log.info("🛡️ [AUDIT] Action={} | PerformedBy={} | Target={} | Meta={} | Time={}",
                    event.getAction(),
                    event.getPerformedBy(),
                    event.getTargetUser(),
                    event.getMetadata(),
                    event.getTimestamp()
            );

            Map<String, Object> logData = Map.of(
                    "action", event.getAction(),
                    "performedBy", event.getPerformedBy(),
                    "targetUser", event.getTargetUser(),
                    "metadata", event.getMetadata(),
                    "timestamp", event.getTimestamp().toString(),
                    "timestampMillis", event.getTimestamp().toEpochMilli()
            );

            return Mono.fromCallable(() ->
                            firestore.collection(AUDIT_COLLECTION).add(logData)
                    )
                    .subscribeOn(Schedulers.boundedElastic())
                    .doOnSuccess(ref -> {
                        try {
                            log.info("✅ Audit log saved at {} with ID: {}",
                                    now, ref.get().getId());
                        } catch (Exception e) {
                            log.error("Failed to get document ID: {}", e.getMessage());
                        }
                    })
                    .doOnError(e -> log.error("❌ Error saving audit log at {}: {}",
                            now, e.getMessage(), e))
                    .then();

        } catch (Exception e) {
            log.error("🔥 Unexpected error in logEventLog() at {}: {}", now, e.getMessage(), e);
            return Mono.empty();
        }
    }

    /**
     * Log standard audit event with user
     */
    public Mono<Void> logAudit(User user, ActionType actionType, String details, String ipAddress) {
        Instant now = clock.instant();

        Map<String, Object> logData = new HashMap<>();
        logData.put("userId", user.getId());
        logData.put("userEmail", user.getEmail());
        logData.put("actionType", actionType.name());
        logData.put("details", details);
        logData.put("ipAddress", ipAddress);
        logData.put("timestamp", now.toString());
        logData.put("timestampMillis", now.toEpochMilli());
        logData.put("firestoreTimestamp", Timestamp.now());

        return FirestoreUtils.apiFutureToMono(firestore.collection(AUDIT_COLLECTION).add(logData))
                .doOnSuccess(docRef -> log.info("✅ Audit log saved at {} for user: {}",
                        now, HelperUtils.maskEmail(user.getEmail())))
                .doOnError(e -> log.error("❌ Error saving audit log at {}: {}", now, e.getMessage()))
                .then();
    }

    /**
     * Log audit event for bootstrap operations
     */
    public Mono<Void> logAuditEventBootstrap(
            User user,
            ActionType action,
            String details,
            String ipAddress) {

        Instant now = clock.instant();

        Map<String, Object> auditData = new HashMap<>();
        auditData.put("timestamp", now.toString());
        auditData.put("timestampMillis", now.toEpochMilli());
        auditData.put("userId", user != null ? user.getId() : null);
        auditData.put("email", user != null ? HelperUtils.maskEmail(user.getEmail()) : null);
        auditData.put("action", action.name());
        auditData.put("details", details);
        auditData.put("ipAddress", ipAddress);

        return Mono.fromRunnable(() -> {
            try {
                firestore.collection(AUDIT_COLLECTION)
                        .document(UUID.randomUUID().toString())
                        .set(auditData)
                        .get();

                log.debug("Audit event saved at {}: {}", now, action.name());
            } catch (Exception e) {
                log.error("Failed to save audit log at {}: {}", now, e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /* =========================
       Authentication Audit Logs
       ========================= */

    /**
     * Log authentication failure
     */
    public void logAuthFailure(
            String email,
            String ipAddress,
            String deviceFingerprint,
            String errorMessage) {

        Instant now = clock.instant();

        // Validate inputs
        if (email == null || email.isBlank()) {
            log.warn("Attempted to log auth failure with null/empty email at {}", now);
            return;
        }

        if (ipAddress == null || ipAddress.isBlank()) {
            ipAddress = "UNKNOWN";
        }

        if (deviceFingerprint == null || deviceFingerprint.isBlank()) {
            deviceFingerprint = "UNKNOWN";
        }

        if (errorMessage == null || errorMessage.isBlank()) {
            errorMessage = "Unknown authentication error";
        }

        log.warn("Authentication failure at {} for: {} from IP: {} device: {} - Error: {}",
                now, HelperUtils.maskEmail(email), ipAddress, deviceFingerprint, errorMessage);

        Map<String, Object> logEntry = new HashMap<>();
        logEntry.put("eventType", "AUTH_FAILURE");
        logEntry.put("email", HelperUtils.maskEmail(email));
        logEntry.put("ipAddress", ipAddress);
        logEntry.put("deviceFingerprint", deviceFingerprint);
        logEntry.put("errorMessage", errorMessage);
        logEntry.put("timestamp", now.toString());
        logEntry.put("timestampMillis", now.toEpochMilli());

        try {
            firestore.collection(AUDIT_COLLECTION).add(logEntry).get();
            log.debug("Auth failure logged successfully at {}", now);
        } catch (Exception e) {
            log.error("Failed to log auth failure at {}: {}", now, e.getMessage(), e);
        }
    }

    /**
     * Log login attempt
     */
    public void logLoginAttempt(String email, String ipAddress, boolean success) {
        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry(
                success ? "LOGIN_SUCCESS" : "LOGIN_FAILURE", now);
        logEntry.put("email", HelperUtils.maskEmail(email));
        logEntry.put("ipAddress", ipAddress);
        if (!success) {
            logEntry.put("severity", "WARNING");
        }

        saveAuditLog(logEntry, now);

        log.info("Login {} at {} for: {}",
                success ? "SUCCESS" : "FAILURE", now, HelperUtils.maskEmail(email));
    }

    /* =========================
       Registration Audit Logs
       ========================= */

    /**
     * Log registration attempt
     */
    public void logRegistrationAttempt(String email, Set<Roles> roles, String ipAddress) {
        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry("REGISTRATION_ATTEMPT", now);
        logEntry.put("email", HelperUtils.maskEmail(email));
        logEntry.put("requestedRoles", roles.stream()
                .map(Roles::name)
                .collect(Collectors.toSet()));
        logEntry.put("ipAddress", ipAddress);

        saveAuditLog(logEntry, now);

        log.info("📝 Registration attempt at {} for {} with roles {} from IP {}",
                now, HelperUtils.maskEmail(email), roles, ipAddress);
    }

    /**
     * Log successful registration
     */
    public void logRegistrationSuccess(
            String email,
            Set<Roles> roles,
            UserStatus status,
            String ipAddress) {

        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry("REGISTRATION_SUCCESS", now);
        logEntry.put("email", HelperUtils.maskEmail(email));
        logEntry.put("roles", roles.stream()
                .map(Roles::name)
                .collect(Collectors.toSet()));
        logEntry.put("status", status.name());
        logEntry.put("ipAddress", ipAddress);

        saveAuditLog(logEntry, now);

        log.info("📝 Registration successful at {} for {} (Status: {})",
                now, HelperUtils.maskEmail(email), status);
    }

    /**
     * Log registration failure
     */
    public void logRegistrationFailure(String email, String reason, String ipAddress) {
        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry("REGISTRATION_FAILURE", now);
        logEntry.put("email", HelperUtils.maskEmail(email));
        logEntry.put("reason", reason);
        logEntry.put("ipAddress", ipAddress);
        logEntry.put("severity", "WARNING");

        saveAuditLog(logEntry, now);

        log.warn("📝 Registration failed at {} for {} - Reason: {}",
                now, HelperUtils.maskEmail(email), reason);
    }

    /* =========================
       Role & Approval Audit Logs
       ========================= */

    /**
     * Log role assignment
     */
    public void logRoleAssignment(String userId, String role, String assignedBy) {
        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry("ROLE_ASSIGNED", now);
        logEntry.put("userId", userId);
        logEntry.put("role", role);
        logEntry.put("assignedBy", assignedBy);

        saveAuditLog(logEntry, now);

        log.info("📝 Role {} assigned at {} to user {} by {}", role, now, userId, assignedBy);
    }

    /**
     * Log role assignment failure
     */
    public void logRoleAssignmentFailure(String userId, String role, String error) {
        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry("ROLE_ASSIGNMENT_FAILURE", now);
        logEntry.put("userId", userId);
        logEntry.put("role", role);
        logEntry.put("error", error);
        logEntry.put("severity", "ERROR");

        saveAuditLog(logEntry, now);

        log.error("📝 Role assignment failed at {} for user {} - Role: {}, Error: {}",
                now, userId, role, error);
    }

    /**
     * Log approval/rejection action
     */
    public void logApprovalAction(
            String userId,
            String actionBy,
            String action,
            String approverRole) {
        logApprovalAction(userId, actionBy, action, approverRole, null);
    }

    public void logApprovalAction(
            String userId,
            String actionBy,
            String action,
            String approverRole,
            String reason) {

        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry("APPROVAL_ACTION", now);
        logEntry.put("userId", userId);
        logEntry.put("action", action);
        logEntry.put("actionBy", actionBy);
        logEntry.put("approverRole", approverRole);
        if (reason != null) {
            logEntry.put("reason", reason);
        }

        saveAuditLog(logEntry, now);

        log.info("📝 User {} {} at {} by {} ({})",
                userId, action, now, actionBy, approverRole);
    }

    /**
     * Log unauthorized approval attempt
     */
    public void logUnauthorizedApproval(String userId, String attemptedBy, String role) {
        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry("UNAUTHORIZED_APPROVAL_ATTEMPT", now);
        logEntry.put("userId", userId);
        logEntry.put("attemptedBy", attemptedBy);
        logEntry.put("attemptedByRole", role);
        logEntry.put("severity", "SECURITY_VIOLATION");

        saveAuditLog(logEntry, now);

        log.warn("🚨 Unauthorized approval attempt at {} on user {} by {} ({})",
                now, userId, attemptedBy, role);
    }

    /* =========================
       User Event Audit Logs
       ========================= */

    /**
     * Log user event with full details
     */
    public Mono<Void> logUserEvent(
            User user,
            ActionType actionType,
            String details,
            String ipAddress
    ) {
        return Mono.fromCallable(() -> {
                    Instant now = clock.instant();

                    Map<String, Object> logData = new HashMap<>();
                    logData.put("userId", user.getId());
                    logData.put("userEmail", HelperUtils.maskEmail(user.getEmail()));
                    logData.put("actionType", actionType.name());
                    logData.put("details", details);
                    logData.put("ipAddress", ipAddress);
                    logData.put("timestamp", now.toString());
                    logData.put("timestampMillis", now.toEpochMilli());
                    logData.put("firestoreTimestamp", Timestamp.now());

                    // ❗ blocking call
                    firestore.collection(AUDIT_COLLECTION).add(logData).get();

                    log.info("User audit logged at {} - User: {}, Action: {}, Details: {}",
                            now, HelperUtils.maskEmail(user.getEmail()), actionType, details);

                    return true;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then()
                .onErrorResume(e -> {
                    Instant now = clock.instant();

                    log.error("Failed to log user audit event at {} for {}: {}",
                            now, HelperUtils.maskEmail(user.getEmail()), e.getMessage(), e);

                    // Best-effort fallback
                    return Mono.fromRunnable(() ->
                                    logSystemEvent("USER_AUDIT_LOG_FAILURE",
                                            "Failed to log user event at " + now + " for " +
                                                    HelperUtils.maskEmail(user.getEmail()) + ": " + e.getMessage())
                            )
                            .subscribeOn(Schedulers.boundedElastic())
                            .then();
                });
    }


    /**
     * Log simple user action
     */
    public void logUserEvent(String userId, String action, String details) {
        Instant now = clock.instant();

        try {
            Map<String, Object> logData = new HashMap<>();
            logData.put("userId", userId);
            logData.put("action", action);
            logData.put("details", details);
            logData.put("timestamp", now.toString());
            logData.put("timestampMillis", now.toEpochMilli());
            logData.put("firestoreTimestamp", Timestamp.now());

            firestore.collection(AUDIT_COLLECTION).add(logData).get();

            log.info("User action logged at {} - User: {}, Action: {}", now, userId, action);
        } catch (Exception e) {
            log.error("Failed to log user action at {} for {}: {}", now, userId, e.getMessage(), e);
            logSystemEvent("USER_ACTION_LOG_FAILURE",
                    "Failed to log action '" + action + "' for user " + userId + " at " + now);
        }
    }

    /**
     * Log account status change
     */
    public void logStatusChange(
            String userId,
            String oldStatus,
            String newStatus,
            String changedBy) {

        Instant now = clock.instant();

        Map<String, Object> logEntry = createBaseLogEntry("STATUS_CHANGE", now);
        logEntry.put("userId", userId);
        logEntry.put("oldStatus", oldStatus);
        logEntry.put("newStatus", newStatus);
        logEntry.put("changedBy", changedBy);

        saveAuditLog(logEntry, now);

        log.info("📝 User {} status changed at {} from {} to {} by {}",
                userId, now, oldStatus, newStatus, changedBy);
    }

    /* =========================
       Password Audit Logs
       ========================= */

    /**
     * Log password change
     */
    public Mono<Void> logPasswordChange(String userId, String ipAddress) {
        Instant now = clock.instant();

        return currentUserProvider.getCurrentUserId()
                .defaultIfEmpty("system")
                .flatMap(actorId -> {
                    AuditLogEntryPasswordChange entry = AuditLogEntryPasswordChange.builder()
                            .eventType("PASSWORD_CHANGE")
                            .targetUserId(userId)
                            .actorId(actorId)
                            .eventTime(now)
                            .ipAddress(ipAddress)
                            .metadata(Map.of(
                                    "change_type", "user_initiated",
                                    "security_level", "high",
                                    "timestamp", now.toString()
                            ))
                            .build();

                    return FirestoreUtils.apiFutureToMono(
                            firestore.collection(PASSWORD_CHANGE_AUDIT_COLLECTION).add(entry)
                    ).then();
                })
                .doOnSuccess(v -> log.info("✅ Password change logged at {} for user: {}",
                        now, userId))
                .doOnError(e -> log.error("Failed to audit password change at {} for user {}: {}",
                        now, userId, e.getMessage()))
                .onErrorResume(e -> Mono.empty());
    }

    /* =========================
       System Event Audit Logs
       ========================= */

    /**
     * Log system event
     */
    public void logSystemEvent(String eventType, String message) {
        Instant now = clock.instant();

        try {
            Map<String, Object> logData = new HashMap<>();
            logData.put("eventType", eventType);
            logData.put("message", message);
            logData.put("severity", determineSeverity(eventType));
            logData.put("timestamp", now.toString());
            logData.put("timestampMillis", now.toEpochMilli());
            logData.put("firestoreTimestamp", Timestamp.now());
            logData.put("service", "auth-service");

            firestore.collection(SYSTEM_AUDIT_COLLECTION).add(logData).get();

            log.info("System event logged at {} - Type: {}, Message: {}", now, eventType, message);
        } catch (Exception e) {
            log.error("CRITICAL: Failed to log system event at {} '{}': {}. Original message: {}",
                    now, eventType, e.getMessage(), message, e);
        }
    }

    /**
     * Log data operation
     */
    public void logDataOperation(String eventType, String key, String message) {
        Instant now = clock.instant();

        try {
            log.info("Audit Log at {} - Event: {}, Key: {}, Message: {}",
                    now, eventType, key, message);

            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("eventType", eventType);
            logEntry.put("key", key);
            logEntry.put("message", message);
            logEntry.put("timestamp", now.toString());
            logEntry.put("timestampMillis", now.toEpochMilli());
            logEntry.put("firestoreTimestamp", FieldValue.serverTimestamp());

            ApiFuture<DocumentReference> future = firestore.collection(AUDIT_COLLECTION).add(logEntry);
            DocumentReference ref = future.get();

            log.debug("Data operation logged at {} with ID: {}", now, ref.getId());
        } catch (Exception e) {
            log.error("Unexpected error while logging data operation at {}: {}",
                    now, e.getMessage(), e);
        }
    }

    /* =========================
       Security Event Audit Logs
       ========================= */

    /**
     * Log security event
     */
    public void logSecurityEvent(String eventType, String key, String description) {
        Instant now = clock.instant();

        try {
            log.warn("Security Event at {} - Type: {}, Key: {}, Description: {}",
                    now, eventType, key, description);

            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("eventType", eventType);
            logEntry.put("key", key);
            logEntry.put("description", description);
            logEntry.put("timestamp", now.toString());
            logEntry.put("timestampMillis", now.toEpochMilli());
            logEntry.put("firestoreTimestamp", FieldValue.serverTimestamp());

            ApiFuture<DocumentReference> future =
                    firestore.collection(SECURITY_LOGS_COLLECTION).add(logEntry);
            DocumentReference ref = future.get();

            log.debug("Security event logged at {} with ID: {}", now, ref.getId());
        } catch (Exception e) {
            log.error("Unexpected error while logging security event at {}: {}",
                    now, e.getMessage(), e);
        }
    }

    /* =========================
       Device & Cache Audit Logs
       ========================= */

    /**
     * Log device event
     */
    public void logDeviceEvent(String deviceRegistered, DeviceInfo deviceInfo) {
        Instant now = clock.instant();

        try {
            Map<String, Object> logData = new HashMap<>();
            logData.put("deviceRegistered", deviceRegistered);
            logData.put("deviceInfo", deviceInfo);
            logData.put("timestamp", now.toString());
            logData.put("timestampMillis", now.toEpochMilli());
            logData.put("firestoreTimestamp", Timestamp.now());

            firestore.collection(AUDIT_COLLECTION).add(logData).get();

            log.info("Device event logged at {} - Device: {}", now, deviceRegistered);
        } catch (Exception e) {
            log.error("Failed to log device event at {}: {}", now, e.getMessage(), e);
            logSystemEvent("DEVICE_EVENT_LOG_FAILURE",
                    "Failed to log device event at " + now + " for " + deviceRegistered);
        }
    }

    /**
     * Log cache event
     */
    public void logCacheEvent(String eventType, String identifier, String details) {
        Instant now = clock.instant();

        log.debug("Cache Event at {} - Type: {}, Identifier: {}, Details: {}",
                now, eventType, identifier, details);

        Map<String, Object> logEntry = new HashMap<>();
        logEntry.put("eventType", eventType);
        logEntry.put("identifier", identifier);
        logEntry.put("details", details);
        logEntry.put("timestamp", now.toString());
        logEntry.put("timestampMillis", now.toEpochMilli());
        logEntry.put("firestoreTimestamp", FieldValue.serverTimestamp());

        try {
            ApiFuture<DocumentReference> future =
                    firestore.collection(CACHE_LOGS_COLLECTION).add(logEntry);
            DocumentReference ref = future.get();

            log.debug("Cache event logged at {} with ID: {}", now, ref.getId());
        } catch (Exception e) {
            log.error("Unexpected error while logging cache event at {}: {}",
                    now, e.getMessage(), e);
        }
    }

    /* =========================
       Audit Log Retrieval
       ========================= */

    /**
     * Get all audit logs
     */
    public List<AuditLogDTO> getAuditLogs() {
        Instant queryTime = clock.instant();

        log.debug("Fetching all audit logs at {}", queryTime);

        try {
            QuerySnapshot querySnapshot = firestore.collection(AUDIT_COLLECTION).get().get();

            List<AuditLogDTO> logs = querySnapshot.getDocuments().stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());

            log.debug("Retrieved {} audit logs at {}", logs.size(), clock.instant());

            return logs;
        } catch (InterruptedException | ExecutionException e) {
            log.error("Error fetching audit logs at {}: {}", clock.instant(), e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Get audit logs by user
     */
    public List<AuditLogDTO> getAuditLogsByUser(String userId) {
        Instant queryTime = clock.instant();

        log.debug("Fetching audit logs at {} for user: {}", queryTime, userId);

        try {
            QuerySnapshot querySnapshot = firestore.collection(AUDIT_COLLECTION)
                    .whereEqualTo("userId", userId)
                    .get()
                    .get();

            List<AuditLogDTO> logs = querySnapshot.getDocuments().stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());

            log.debug("Retrieved {} audit logs at {} for user: {}",
                    logs.size(), clock.instant(), userId);

            return logs;

        } catch (InterruptedException | ExecutionException e) {
            log.error("Error fetching audit logs at {} for user {}: {}",
                    clock.instant(), userId, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Get audit logs by action type
     */
    public List<AuditLogDTO> getAuditLogsByAction(ActionType actionType) {
        Instant queryTime = clock.instant();

        log.debug("Fetching audit logs at {} for action: {}", queryTime, actionType);

        try {
            QuerySnapshot querySnapshot = firestore.collection(AUDIT_COLLECTION)
                    .whereEqualTo("actionType", actionType.name())
                    .get()
                    .get();

            List<AuditLogDTO> logs = querySnapshot.getDocuments().stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());

            log.debug("Retrieved {} audit logs at {} for action: {}",
                    logs.size(), clock.instant(), actionType);

            return logs;

        } catch (InterruptedException | ExecutionException e) {
            log.error("Error fetching audit logs at {} for action {}: {}",
                    clock.instant(), actionType, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /* =========================
       Real-time Monitoring
       ========================= */

    /**
     * Watch audit logs for real-time changes
     */
    public void watchAuditLogs() {
        Instant watchStart = clock.instant();

        log.info("Starting audit log watch at {}", watchStart);

        firestore.collection(AUDIT_COLLECTION)
                .addSnapshotListener((snapshots, e) -> {
                    Instant eventTime = clock.instant();

                    if (e != null) {
                        log.error("Listen failed at {}: {}", eventTime, e.getMessage(), e);
                        return;
                    }

                    if (snapshots == null || snapshots.isEmpty()) {
                        log.debug("No audit log changes detected at {}", eventTime);
                        return;
                    }

                    for (DocumentChange dc : snapshots.getDocumentChanges()) {
                        switch (dc.getType()) {
                            case ADDED -> log.info("New audit log at {}: {}",
                                    eventTime, dc.getDocument().getData());
                            case MODIFIED -> log.info("Updated audit log at {}: {}",
                                    eventTime, dc.getDocument().getData());
                            case REMOVED -> log.info("Deleted audit log at {}: {}",
                                    eventTime, dc.getDocument().getData());
                        }
                    }
                });
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Create base log entry with timestamp
     */
    private Map<String, Object> createBaseLogEntry(String eventType, Instant timestamp) {
        Map<String, Object> entry = new HashMap<>();
        entry.put("eventType", eventType);
        entry.put("timestamp", timestamp.toString());
        entry.put("timestampMillis", timestamp.toEpochMilli());
        return entry;
    }

    /**
     * Save audit log to Firestore
     */
    private void saveAuditLog(Map<String, Object> logEntry, Instant logTime) {
        try {
            firestore.collection(AUDIT_COLLECTION).add(logEntry);
            log.debug("Audit log saved at {}", logTime);
        } catch (Exception e) {
            log.error("⚠️ Failed to save audit log at {}: {}", logTime, e.getMessage());
        }
    }

    /**
     * Determine severity from event type
     */
    private String determineSeverity(String eventType) {
        if (eventType.contains("FAILURE") || eventType.contains("ERROR") ||
                eventType.contains("CRITICAL")) {
            return "HIGH";
        } else if (eventType.contains("WARNING") || eventType.contains("ALERT")) {
            return "MEDIUM";
        }
        return "LOW";
    }

    /**
     * Convert Firestore document to DTO
     */
    private AuditLogDTO convertToDTO(QueryDocumentSnapshot doc) {
        AuditLogDTO dto = new AuditLogDTO();

        try {
            dto.setId(doc.getId());
            dto.setUserId(doc.getString("userId"));
            dto.setCreatedAt(doc.getDate("createdAt"));

            String actionType = doc.getString("actionType");
            if (actionType != null) {
                dto.setActionType(ActionType.valueOf(actionType));
            }

            dto.setIpAddress(doc.getString("ipAddress"));
            dto.setDetails(doc.getString("details"));
        } catch (Exception e) {
            log.error("Error converting document to DTO at {}: {}",
                    clock.instant(), e.getMessage());
        }

        return dto;
    }
}