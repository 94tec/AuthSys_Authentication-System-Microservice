package com.techStack.authSys.service;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.google.firebase.cloud.FirestoreClient;
import com.techStack.authSys.dto.AuditLogDTO;
import com.techStack.authSys.models.*;
import com.techStack.authSys.repository.AuditLogRepository;
import com.techStack.authSys.security.CurrentUserProvider;
import com.techStack.authSys.util.FirestoreUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@RedisHash("AuditLogs")
@Service
public class AuditLogService {
    private static final Logger logger = LoggerFactory.getLogger(AuditLogService.class);
    private static final String COLLECTION_NAME = "audit_logs";
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
                            firestore.collection(COLLECTION_NAME).add(logData)
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

    public Mono<Void> logAudit(User user, ActionType actionType, String details, String ipAddress) {
        Map<String, Object> logData = new HashMap<>();
        logData.put("userId", user.getId());
        logData.put("actionType", actionType.name());
        logData.put("details", details);
        logData.put("ipAddress", ipAddress);
        logData.put("createdAt", Timestamp.now());

        ApiFuture<DocumentReference> future = firestore.collection(COLLECTION_NAME).add(logData);

        return FirestoreUtils.apiFutureToMono(firestore.collection(COLLECTION_NAME).add(logData))
                .doOnSuccess(docRef -> logger.info("✅ Audit log saved"))
                .doOnError(e -> logger.error("❌ Error saving audit log", e))
                .then();

    }

    public void logAuthFailure(String email, String ipAddress, String errorMessage) {
        if (email == null || email.isBlank()) {
            logger.warn("Attempted to log auth failure with a null or empty email");
            return;
        }
        if (ipAddress == null || ipAddress.isBlank()) {
            logger.warn("Attempted to log auth failure with a null or empty IP address for email: {}", email);
            return;
        }
        if (errorMessage == null || errorMessage.isBlank()) {
            logger.warn("Attempted to log auth failure with a null or empty error message for email: {}", email);
            errorMessage = "Unknown authentication error";
        }

        // Log event details
        logger.warn("Authentication failure for email: {} from IP: {} - Error: {}", email, ipAddress, errorMessage);

        // Prepare log entry
        Map<String, Object> logEntry = new HashMap<>();
        logEntry.put("eventType", "AUTH_FAILURE");
        logEntry.put("email", email);
        logEntry.put("ipAddress", ipAddress);
        logEntry.put("errorMessage", errorMessage);
        logEntry.put("timestamp", Instant.now().toString());

        try {
            // Save log entry to Firestore or any other logging system
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
            ApiFuture<DocumentReference> future = firestore.collection(COLLECTION_NAME).add(logEntry);

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
            QuerySnapshot querySnapshot = firestore.collection(COLLECTION_NAME).get().get();
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
            QuerySnapshot querySnapshot = firestore.collection(COLLECTION_NAME)
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
            QuerySnapshot querySnapshot = firestore.collection(COLLECTION_NAME)
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
        firestore.collection(COLLECTION_NAME)
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

            firestore.collection(COLLECTION_NAME).add(logData).get();

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

            firestore.collection(COLLECTION_NAME).add(logData).get();

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

            firestore.collection(COLLECTION_NAME).add(logData).get();

            logger.info("User action logged - User: {}, Action: {}", deviceRegistered, deviceInfo);
        } catch (Exception e) {
            logger.error("Failed to log user action for {}: {}", deviceRegistered, e.getMessage(), e);
            logSystemEvent("USER_ACTION_LOG_FAILURE",
                    "Failed to log action '" + deviceInfo + "' for user " + deviceRegistered);

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
