package com.techStack.authSys.service.observability;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.google.firebase.cloud.FirestoreClient;
import com.techStack.authSys.dto.response.AuditLogDTO;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.audit.AuditEventLog;
import com.techStack.authSys.models.audit.AuditLogEntryPasswordChange;
import com.techStack.authSys.models.session.DeviceInfo;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.security.context.CurrentUserProvider;
import com.techStack.authSys.util.firebase.FirestoreUtils;
import com.techStack.authSys.util.validation.HelperUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@RedisHash("AuditLogs")
@Service
public class AuditLogService {
    private static final Logger logger = LoggerFactory.getLogger(AuditLogService.class);
    private static final String AUDIT_COLLECTION = "audit_logs";
    private static final String SYSTEM_AUDIT_COLLECTION = "system_audit_logs";
    private static final String PASSWORD_CHANGE_AUDIT_COLLECTION = "password_change_logs";

    private final Firestore firestore;
    private final Clock clock;
    private final CurrentUserProvider currentUserProvider;

    public AuditLogService(Firestore firestore,
                           Clock clock,
                           CurrentUserProvider currentUserProvider
                          ) {
        this.firestore = firestore;
        this.clock = clock;
        this.currentUserProvider = currentUserProvider;
    }
    /**
     * Logs a transaction failure with rollback details.
     */
    public void logTransactionFailure(
            String operation,
            String userId,
            String error,
            Map<String, Object> context) {

        Map<String, Object> auditData = new HashMap<>();
        auditData.put("timestamp", LocalDateTime.now().toString());
        auditData.put("operation", operation);
        auditData.put("userId", userId);
        auditData.put("status", "ROLLBACK_TRIGGERED");
        auditData.put("error", error);
        auditData.put("context", context);
        auditData.put("severity", "CRITICAL");

        try {
            firestore.collection("audit_rollbacks")
                    .document(UUID.randomUUID().toString())
                    .set(auditData)
                    .get();
            logger.warn("📋 Critical rollback logged for operation: {}", operation);
        } catch (Exception e) {
            logger.error("❌ Failed to log rollback: {}", e.getMessage());
        }
    }

    /**
     * Logs partial save scenarios requiring manual cleanup.
     */
    public void logPartialSave(
            String userId,
            Map<String, String> savedCollections,
            String failedCollection) {

        Map<String, Object> partialSaveData = new HashMap<>();
        partialSaveData.put("timestamp", LocalDateTime.now().toString());
        partialSaveData.put("userId", userId);
        partialSaveData.put("savedCollections", savedCollections);
        partialSaveData.put("failedCollection", failedCollection);
        partialSaveData.put("action", "REQUIRES_MANUAL_CLEANUP");
        partialSaveData.put("severity", "HIGH");

        try {
            firestore.collection("audit_partial_saves")
                    .document(UUID.randomUUID().toString())
                    .set(partialSaveData)
                    .get();
            logger.warn("⚠️ Partial save logged - manual cleanup required");
        } catch (Exception e) {
            logger.error("❌ Failed to log partial save: {}", e.getMessage());
        }
    }

    /**
     * Logs successful bootstrap completion.
     */
    public Mono<Void> logBootstrapSuccess(String email, long durationMs) {
        Map<String, Object> auditData = Map.of(
                "timestamp", LocalDateTime.now().toString(),
                "operation", "SUPER_ADMIN_BOOTSTRAP",
                "status", "SUCCESS",
                "email", HelperUtils.maskEmail(email),
                "durationMs", durationMs
        );

        return Mono.fromRunnable(() -> {
            try {
                firestore.collection("audit_bootstrap")
                        .document(UUID.randomUUID().toString())
                        .set(auditData)
                        .get();
            } catch (Exception e) {
                logger.error("Failed to log bootstrap success: {}", e.getMessage());
            }
        });
    }

    public Mono<Void> logEventLog(AuditEventLog event) {
        try {
            logger.info("🛡️ [AUDIT] Action={} | PerformedBy={} | Target={} | Meta={} | Time={}",
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
                    "timestamp", event.getTimestamp()
            );

            // Push Firestore write to boundedElastic to avoid blocking main threads
            return Mono.fromCallable(() ->
                            firestore.collection(AUDIT_COLLECTION).add(logData)
                    )
                    .subscribeOn(Schedulers.boundedElastic())
                    .doOnSuccess(ref -> {
                        try {
                            logger.info("✅ Audit log saved with ID: {}", ref.get().getId());
                        } catch (InterruptedException e) {
                            throw new RuntimeException(e);
                        } catch (ExecutionException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .doOnError(e -> logger.error("❌ Error saving audit log: {}", e.getMessage(), e))
                    .then();

        } catch (Exception e) {
            logger.error("🔥 Unexpected error in logEventLog(): {}", e.getMessage(), e);
            return Mono.empty(); // Failsafe fallback
        }
    }
    /**
     * Log registration attempt
     * Document recommendation: "Log all registration attempts for auditability"
     */
    public void logRegistrationAttempt(String email, Set<Roles> roles, String ipAddress) {
        Map<String, Object> logEntry = createBaseLogEntry("REGISTRATION_ATTEMPT");
        logEntry.put("email", email);
        logEntry.put("requestedRoles", roles.toString());
        logEntry.put("ipAddress", ipAddress);

        saveAuditLog(logEntry);
        logger.info("📝 Audit: Registration attempt for {} with roles {} from IP {}",
                email, roles, ipAddress);

    }
    public Mono<Void> logAudit(User user, ActionType actionType, String details, String ipAddress) {
        Map<String, Object> logData = new HashMap<>();
        logData.put("userId", user.getId());
        logData.put("actionType", actionType.name());
        logData.put("details", details);
        logData.put("ipAddress", ipAddress);
        logData.put("createdAt", Timestamp.now());

        ApiFuture<DocumentReference> future = firestore.collection(AUDIT_COLLECTION).add(logData);

        return FirestoreUtils.apiFutureToMono(firestore.collection(AUDIT_COLLECTION).add(logData))
                .doOnSuccess(docRef -> logger.info("✅ Audit log saved"))
                .doOnError(e -> logger.error("❌ Error saving audit log", e))
                .then();

    }
    /**
     * Logs a standard audit event.
     */
    public Mono<Void> logAuditEventBootstrap(
            User user,
            ActionType action,
            String details,
            String ipAddress) {

        Map<String, Object> auditData = new HashMap<>();
        auditData.put("timestamp", LocalDateTime.now().toString());
        auditData.put("userId", user != null ? user.getId() : null);
        auditData.put("email", user != null ? user.getEmail() : null);
        auditData.put("action", action.name());
        auditData.put("details", details);
        auditData.put("ipAddress", ipAddress);

        return Mono.fromRunnable(() -> {
            try {
                firestore.collection("audit_logs")
                        .document(UUID.randomUUID().toString())
                        .set(auditData)
                        .get();
            } catch (Exception e) {
                logger.error("Failed to save audit log: {}", e.getMessage());
            }
        });
    }

    public void logAuthFailure(String email, String ipAddress, String deviceFingerprint, String errorMessage) {
        if (email == null || email.isBlank()) {
            logger.warn("Attempted to log auth failure with a null or empty email");
            return;
        }
        if (ipAddress == null || ipAddress.isBlank()) {
            logger.warn("Attempted to log auth failure with a null or empty IP address for email: {}", email);
            return;
        }
        if (deviceFingerprint == null || deviceFingerprint.isBlank()) {
            logger.warn("Attempted to log auth failure with a null or empty device fingerprint for email: {}", email);
            deviceFingerprint = "Unknown device";
        }
        if (errorMessage == null || errorMessage.isBlank()) {
            logger.warn("Attempted to log auth failure with a null or empty error message for email: {}", email);
            errorMessage = "Unknown authentication error";
        }

        // Log event details
        logger.warn("Authentication failure for email: {} from IP: {} with device: {} - Error: {}",
                email, ipAddress, deviceFingerprint, errorMessage);

        // Prepare log entry
        Map<String, Object> logEntry = new HashMap<>();
        logEntry.put("eventType", "AUTH_FAILURE");
        logEntry.put("email", email);
        logEntry.put("ipAddress", ipAddress);
        logEntry.put("deviceFingerprint", deviceFingerprint);
        logEntry.put("errorMessage", errorMessage);
        logEntry.put("timestamp", Instant.now().toString());

        try {
            // Save log entry to Firestore
            Firestore firestore = FirestoreClient.getFirestore();
            firestore.collection("audit_logs").add(logEntry).get();
            logger.info("Authentication failure logged successfully for email: {}", email);
        } catch (Exception e) {
            logger.error("Failed to log authentication failure for email: {} - Error: {}", email, e.getMessage(), e);
        }
    }

    public void logDataOperation(String eventType, String key, String message) {
        try {
            logger.error("Audit Log - Event: {}, Key: {}, Message: {}", eventType, key, message);

            // Create log entry
            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("eventType", eventType);
            logEntry.put("key", key);
            logEntry.put("message", message);
            logEntry.put("timestamp", FieldValue.serverTimestamp());

            // Asynchronously save to Firestore
            ApiFuture<DocumentReference> future = firestore.collection(AUDIT_COLLECTION).add(logEntry);

            future.addListener(() -> {
                try {
                    DocumentReference documentReference = future.get();
                    logger.info("Successfully logged event: {} with Key: {}, Document ID: {}",
                            eventType, key, documentReference.getId());
                } catch (Exception e) {
                    logger.error("Failed to retrieve Firestore document reference: {}", e.getMessage(), e);
                }
            }, Executors.newSingleThreadExecutor());

        } catch (Exception e) {
            logger.error("Unexpected error while logging data operation: {}", e.getMessage(), e);
        }
    }

    public void logSecurityEvent(String eventType, String key, String description) {
        try {
            logger.warn("Security Event - Type: {}, Key: {}, Description: {}", eventType, key, description);

            // Create structured log entry
            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("eventType", eventType);
            logEntry.put("key", key);
            logEntry.put("description", description);
            logEntry.put("timestamp", FieldValue.serverTimestamp());

            // Save log to Firestore asynchronously
            ApiFuture<DocumentReference> future = firestore.collection("security_logs").add(logEntry);

            future.addListener(() -> {
                try {
                    DocumentReference documentReference = future.get();
                    logger.info("Security event logged successfully: {} with Key: {}, Document ID: {}",
                            eventType, key, documentReference.getId());
                } catch (Exception e) {
                    logger.error("Failed to retrieve Firestore document reference: {}", e.getMessage(), e);
                }
            }, Executors.newSingleThreadExecutor());

        } catch (Exception e) {
            logger.error("Unexpected error while logging security event: {}", e.getMessage(), e);
        }
    }
    public void logCacheEvent(String eventType, String identifier, String details) {
        logger.warn("Cache Event - Type: {}, Identifier: {}, Details: {}", eventType, identifier, details);

        // Create structured log entry
        Map<String, Object> logEntry = new HashMap<>();
        logEntry.put("eventType", eventType);
        logEntry.put("identifier", identifier);
        logEntry.put("details", details);
        logEntry.put("timestamp", FieldValue.serverTimestamp());

        // Save log to Firestore asynchronously
        try {
            ApiFuture<DocumentReference> future = firestore.collection("cache_logs").add(logEntry);
            future.addListener(() -> {
                try {
                    DocumentReference documentReference = future.get();
                    logger.info("Cache event logged successfully: {} with Key: {}, Document ID: {}",
                            eventType, identifier, documentReference.getId());
                } catch (Exception e) {
                    logger.error("Failed to retrieve Firestore document reference: {}", e.getMessage(), e);
                }
            }, Executors.newSingleThreadExecutor());
        } catch (Exception e) {
            logger.error("Unexpected error while logging cache event: {}", e.getMessage(), e);
        }
    }

    public List<AuditLogDTO> getAuditLogs() {
        try {
            QuerySnapshot querySnapshot = firestore.collection(AUDIT_COLLECTION).get().get();
            return querySnapshot.getDocuments().stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());
        } catch (InterruptedException | ExecutionException e) {
            logger.error("Error fetching audit logs: {}", e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    public List<AuditLogDTO> getAuditLogsByUser(String userId) {
        try {
            QuerySnapshot querySnapshot = firestore.collection(AUDIT_COLLECTION)
                    .whereEqualTo("userId", userId)
                    .get()
                    .get();

            return querySnapshot.getDocuments().stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());

        } catch (InterruptedException | ExecutionException e) {
            logger.error("Error fetching audit logs for user {}: {}", userId, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    public List<AuditLogDTO> getAuditLogsByAction(ActionType actionType) {
        try {
            QuerySnapshot querySnapshot = firestore.collection(AUDIT_COLLECTION)
                    .whereEqualTo("actionType", actionType.name())
                    .get()
                    .get();

            return querySnapshot.getDocuments().stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());

        } catch (InterruptedException | ExecutionException e) {
            logger.error("Error fetching audit logs for action {}: {}", actionType, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    public void watchAuditLogs() {
        firestore.collection(AUDIT_COLLECTION)
                .addSnapshotListener((snapshots, e) -> {
                    if (e != null) {
                        logger.error("Listen failed: {}", e.getMessage(), e);
                        return;
                    }

                    if (snapshots == null || snapshots.isEmpty()) {
                        logger.info("No audit log changes detected.");
                        return;
                    }

                    for (DocumentChange dc : snapshots.getDocumentChanges()) {
                        switch (dc.getType()) {
                            case ADDED -> logger.info("New audit log: {}", dc.getDocument().getData());
                            case MODIFIED -> logger.info("Updated audit log: {}", dc.getDocument().getData());
                            case REMOVED -> logger.info("Deleted audit log: {}", dc.getDocument().getData());
                        }
                    }
                });
    }

    public void logUserEvent(User user, ActionType actionType, String details, String ipAddress) {
        try {
            Map<String, Object> logData = new HashMap<>();
            logData.put("userId", user.getId());
            logData.put("userEmail", user.getEmail());
            logData.put("actionType", actionType.name());
            logData.put("details", details);
            logData.put("ipAddress", ipAddress);
            logData.put("timestamp", Timestamp.now());
            logData.put("eventDate", Date.from(clock.instant()));

            firestore.collection(AUDIT_COLLECTION).add(logData).get();

            logger.info("User audit logged - User: {}, Action: {}, Details: {}",
                    user.getEmail(), actionType, details);
        } catch (Exception e) {
            logger.error("Failed to log user audit event for {}: {}", user.getEmail(), e.getMessage(), e);
            logSystemEvent("USER_AUDIT_LOG_FAILURE",
                    "Failed to log user event for " + user.getEmail() + ": " + e.getMessage());
        }
    }

    public void logSystemEvent(String eventType, String message) {
        try {
            Map<String, Object> logData = new HashMap<>();
            logData.put("eventType", eventType);
            logData.put("message", message);
            logData.put("severity", determineSeverity(eventType));
            logData.put("timestamp", Timestamp.now());
            logData.put("eventDate", Date.from(clock.instant()));
            logData.put("service", "security-automation-service");

            firestore.collection(SYSTEM_AUDIT_COLLECTION).add(logData).get();

            logger.info("System event logged - Type: {}, Message: {}", eventType, message);
        } catch (Exception e) {
            logger.error("CRITICAL: Failed to log system event '{}': {}. Original message: {}",
                    eventType, e.getMessage(), message, e);
        }
    }

    public void logUserEvent(String userId, String action, String details) {
        try {
            Map<String, Object> logData = new HashMap<>();
            logData.put("userId", userId);
            logData.put("action", action);
            logData.put("details", details);
            logData.put("timestamp", Timestamp.now());

            firestore.collection(AUDIT_COLLECTION).add(logData).get();

            logger.info("User action logged - User: {}, Action: {}", userId, action);
        } catch (Exception e) {
            logger.error("Failed to log user action for {}: {}", userId, e.getMessage(), e);
            logSystemEvent("USER_ACTION_LOG_FAILURE",
                    "Failed to log action '" + action + "' for user " + userId);
        }
    }
    public void logDeviceEvent(String deviceRegistered, DeviceInfo deviceInfo) {
        try {
            Map<String, Object> logData = new HashMap<>();
            logData.put("deviceRegistered", deviceRegistered);
            logData.put("deviceInfo", deviceInfo);
            logData.put("timestamp", Timestamp.now());

            firestore.collection(AUDIT_COLLECTION).add(logData).get();

            logger.info("User action logged - User: {}, Action: {}", deviceRegistered, deviceInfo);
        } catch (Exception e) {
            logger.error("Failed to log user action for {}: {}", deviceRegistered, e.getMessage(), e);
            logSystemEvent("USER_ACTION_LOG_FAILURE",
                    "Failed to log action '" + deviceInfo + "' for user " + deviceRegistered);

        }
    }
        /**
         * Log successful registration
         */
        public void logRegistrationSuccess(String email, Set<Roles> roles, String status, String ipAddress) {
            Map<String, Object> logEntry = createBaseLogEntry("REGISTRATION_SUCCESS");
            logEntry.put("email", email);
            logEntry.put("roles", roles.toString());
            logEntry.put("status", status);
            logEntry.put("ipAddress", ipAddress);

            saveAuditLog(logEntry);
            logger.info("📝 Audit: Registration successful for {} (Status: {})", email, status);
        }

        /**
         * Log registration failure
         */
        public void logRegistrationFailure(String email, String reason, String ipAddress) {
            Map<String, Object> logEntry = createBaseLogEntry("REGISTRATION_FAILURE");
            logEntry.put("email", email);
            logEntry.put("reason", reason);
            logEntry.put("ipAddress", ipAddress);
            logEntry.put("severity", "WARNING");

            saveAuditLog(logEntry);
            logger.warn("📝 Audit: Registration failed for {} - Reason: {}", email, reason);
        }

        /**
         * Log role assignment
         */
        public void logRoleAssignment(String userId, String role, String assignedBy) {
            Map<String, Object> logEntry = createBaseLogEntry("ROLE_ASSIGNED");
            logEntry.put("userId", userId);
            logEntry.put("role", role);
            logEntry.put("assignedBy", assignedBy);

            saveAuditLog(logEntry);
            logger.info("📝 Audit: Role {} assigned to user {} by {}", role, userId, assignedBy);
        }

        /**
         * Log role assignment failure
         */
        public void logRoleAssignmentFailure(String userId, String role, String error) {
            Map<String, Object> logEntry = createBaseLogEntry("ROLE_ASSIGNMENT_FAILURE");
            logEntry.put("userId", userId);
            logEntry.put("role", role);
            logEntry.put("error", error);
            logEntry.put("severity", "ERROR");

            saveAuditLog(logEntry);
            logger.error("📝 Audit: Role assignment failed for user {} - Role: {}, Error: {}",
                    userId, role, error);
        }

        /**
         * Log approval/rejection action
         * Document recommendation: "Log all approval decisions for auditability"
         */
        public void logApprovalAction(String userId, String actionBy, String action, String approverRole) {
            logApprovalAction(userId, actionBy, action, approverRole, null);
        }

        public void logApprovalAction(String userId, String actionBy, String action,
                String approverRole, String reason) {
            Map<String, Object> logEntry = createBaseLogEntry("APPROVAL_ACTION");
            logEntry.put("userId", userId);
            logEntry.put("action", action); // APPROVED or REJECTED
            logEntry.put("actionBy", actionBy);
            logEntry.put("approverRole", approverRole);
            if (reason != null) {
                logEntry.put("reason", reason);
            }

            saveAuditLog(logEntry);
            logger.info("📝 Audit: User {} {} by {} ({})", userId, action, actionBy, approverRole);
        }

        /**
         * Log unauthorized approval attempt
         */
        public void logUnauthorizedApproval(String userId, String attemptedBy, String role) {
            Map<String, Object> logEntry = createBaseLogEntry("UNAUTHORIZED_APPROVAL_ATTEMPT");
            logEntry.put("userId", userId);
            logEntry.put("attemptedBy", attemptedBy);
            logEntry.put("attemptedByRole", role);
            logEntry.put("severity", "SECURITY_VIOLATION");

            saveAuditLog(logEntry);
            logger.warn("🚨 Audit: Unauthorized approval attempt on user {} by {} ({})",
                    userId, attemptedBy, role);
        }

        /**
         * Log login attempt
         */
        public void logLoginAttempt(String email, String ipAddress, boolean success) {
            Map<String, Object> logEntry = createBaseLogEntry(success ? "LOGIN_SUCCESS" : "LOGIN_FAILURE");
            logEntry.put("email", email);
            logEntry.put("ipAddress", ipAddress);
            if (!success) {
                logEntry.put("severity", "WARNING");
            }

            saveAuditLog(logEntry);
        }

        /**
         * Log account status change
         */
        public void logStatusChange(String userId, String oldStatus, String newStatus, String changedBy) {
            Map<String, Object> logEntry = createBaseLogEntry("STATUS_CHANGE");
            logEntry.put("userId", userId);
            logEntry.put("oldStatus", oldStatus);
            logEntry.put("newStatus", newStatus);
            logEntry.put("changedBy", changedBy);

            saveAuditLog(logEntry);
            logger.info("📝 Audit: User {} status changed from {} to {} by {}",
                    userId, oldStatus, newStatus, changedBy);
        }

        private Map<String, Object> createBaseLogEntry(String eventType) {
            Map<String, Object> entry = new HashMap<>();
            entry.put("eventType", eventType);
            entry.put("timestamp", Instant.now().toString());
            entry.put("timestampMillis", System.currentTimeMillis());
            return entry;
        }

        private void saveAuditLog(Map<String, Object> logEntry) {
            try {
                firestore.collection(AUDIT_COLLECTION).add(logEntry);
            } catch (Exception e) {
                // Never fail operation due to audit log failure
                logger.error("⚠️ Failed to save audit log: {}", e.getMessage());
            }
        }
    public Mono<Void> logPasswordChange(String userId, String ipAddress) {
        return currentUserProvider.getCurrentUserId()
                .defaultIfEmpty("system") // fallback for system-initiated changes
                .flatMap(actorId -> {
                    AuditLogEntryPasswordChange entry = AuditLogEntryPasswordChange.builder()
                            .eventType("PASSWORD_CHANGE")
                            .targetUserId(userId)
                            .actorId(actorId)
                            .eventTime(Instant.now(clock))
                            .ipAddress(ipAddress) // implement this
                            .metadata(Map.of(
                                    "change_type", "user_initiated",
                                    "security_level", "high"
                            ))
                            .build();

                    return FirestoreUtils.apiFutureToMono(firestore.collection(PASSWORD_CHANGE_AUDIT_COLLECTION).add(entry)).then();
                })
                .doOnError(e -> logger.error("Failed to audit password change for user {}", userId, e))
                .onErrorResume(e -> Mono.empty()); // don't fail password change if audit fails
    }
    private String determineSeverity(String eventType) {
        if (eventType.contains("FAILURE") || eventType.contains("ERROR")) {
            return "HIGH";
        } else if (eventType.contains("WARNING") || eventType.contains("ALERT")) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private AuditLogDTO convertToDTO(QueryDocumentSnapshot doc) {
        AuditLogDTO dto = new AuditLogDTO();
        dto.setId(String.valueOf(UUID.fromString(doc.getId())));
        dto.setUserId(String.valueOf(UUID.fromString(doc.getString("userId"))));
        dto.setCreatedAt(doc.getDate("createdAt"));
        dto.setActionType(ActionType.valueOf(doc.getString("actionType")));
        dto.setIpAddress(doc.getString("ipAddress"));
        dto.setDetails(doc.getString("details"));
        return dto;
    }
}
