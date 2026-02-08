package com.techStack.authSys.service.bootstrap;


import com.google.cloud.firestore.AggregateQuerySnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.Query;
import com.google.cloud.firestore.QuerySnapshot;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Monitors bootstrap health and provides diagnostic information.
 * Useful for debugging and operations.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapMonitoringService {

    private final Firestore firestore;
    private final BootstrapStateService stateService;

    /**
     * Gets comprehensive bootstrap health status.
     */
    public Mono<BootstrapHealthReport> getBootstrapHealth() {
        return Mono.fromCallable(() -> {
            BootstrapHealthReport report = new BootstrapHealthReport();

            // Check if bootstrap is complete
            report.isComplete = Boolean.TRUE.equals(stateService.isBootstrapCompleted().block());

            // Count critical failures
            report.criticalFailures = countCriticalFailures();

            // Count recent rollbacks
            report.recentRollbacks = countRecentRollbacks(24); // Last 24 hours

            // Count partial saves
            report.partialSaves = countPartialSaves();

            // Get last bootstrap attempt
            report.lastAttempt = getLastBootstrapAttempt();

            // Overall health
            report.health = determineHealth(report);

            return report;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Gets all critical failures requiring manual intervention.
     */
    public Mono<List<CriticalFailure>> getCriticalFailures() {
        return Mono.fromCallable(() -> {
            List<CriticalFailure> failures = new ArrayList<>();

            try {
                QuerySnapshot snapshot = firestore.collection("audit_critical_failures")
                        .whereEqualTo("requiresManualCleanup", true)
                        .limit(50)
                        .get()
                        .get();

                snapshot.getDocuments().forEach(doc -> {
                    CriticalFailure failure = new CriticalFailure();
                    failure.id = doc.getId();
                    failure.timestamp = doc.getString("timestamp");
                    failure.operation = doc.getString("operation");
                    failure.originalError = doc.getString("originalError");
                    failure.rollbackError = doc.getString("rollbackError");
                    failure.failurePoint = doc.getString("failurePoint");
                    failure.context = (Map<String, Object>) doc.get("context");
                    failures.add(failure);
                });
            } catch (Exception e) {
                log.error("Failed to get critical failures: {}", e.getMessage());
            }

            return failures;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Gets recent rollback events.
     */
    public Mono<List<RollbackEvent>> getRecentRollbacks(int hours) {
        return Mono.fromCallable(() -> {
            List<RollbackEvent> rollbacks = new ArrayList<>();

            try {
                QuerySnapshot snapshot = firestore.collection("audit_rollbacks")
                        .orderBy("timestamp", Query.Direction.DESCENDING)
                        .limit(100)
                        .get()
                        .get();

                Instant cutoff = Instant.now().minus(hours, ChronoUnit.HOURS);

                snapshot.getDocuments().forEach(doc -> {
                    String timestampStr = doc.getString("timestamp");
                    if (timestampStr != null) {
                        Instant timestamp = Instant.parse(timestampStr);
                        if (timestamp.isAfter(cutoff)) {
                            RollbackEvent event = new RollbackEvent();
                            event.id = doc.getId();
                            event.timestamp = timestampStr;
                            event.operation = doc.getString("operation");
                            event.userId = doc.getString("userId");
                            event.error = doc.getString("error");
                            event.cleaned = Boolean.TRUE.equals(doc.getBoolean("cleaned"));
                            rollbacks.add(event);
                        }
                    }
                });
            } catch (Exception e) {
                log.error("Failed to get recent rollbacks: {}", e.getMessage());
            }

            return rollbacks;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Marks a critical failure as resolved after manual cleanup.
     */
    public Mono<Void> markCriticalFailureResolved(String failureId, String resolution) {
        return Mono.fromRunnable(() -> {
            try {
                firestore.collection("audit_critical_failures")
                        .document(failureId)
                        .update(
                                "requiresManualCleanup", false,
                                "resolved", true,
                                "resolvedAt", Instant.now().toString(),
                                "resolution", resolution
                        )
                        .get();
                log.info("✅ Marked critical failure as resolved: {}", failureId);
            } catch (Exception e) {
                log.error("Failed to mark failure as resolved: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    // Private helper methods

    private int countCriticalFailures() {
        try {
            AggregateQuerySnapshot snapshot = firestore.collection("audit_critical_failures")
                    .whereEqualTo("requiresManualCleanup", true)
                    .count()
                    .get()
                    .get();
            return (int) snapshot.getCount();
        } catch (Exception e) {
            log.error("Failed to count critical failures: {}", e.getMessage());
            return -1;
        }
    }

    private int countRecentRollbacks(int hours) {
        try {
            Instant cutoff = Instant.now().minus(hours, ChronoUnit.HOURS);
            QuerySnapshot snapshot = firestore.collection("audit_rollbacks")
                    .get()
                    .get();

            long count = snapshot.getDocuments().stream()
                    .filter(doc -> {
                        String timestamp = doc.getString("timestamp");
                        if (timestamp != null) {
                            return Instant.parse(timestamp).isAfter(cutoff);
                        }
                        return false;
                    })
                    .count();

            return (int) count;
        } catch (Exception e) {
            log.error("Failed to count recent rollbacks: {}", e.getMessage());
            return -1;
        }
    }

    private int countPartialSaves() {
        try {
            AggregateQuerySnapshot snapshot = firestore.collection("audit_partial_saves")
                    .whereEqualTo("action", "REQUIRES_MANUAL_CLEANUP")
                    .count()
                    .get()
                    .get();
            return (int) snapshot.getCount();
        } catch (Exception e) {
            log.error("Failed to count partial saves: {}", e.getMessage());
            return -1;
        }
    }

    private String getLastBootstrapAttempt() {
        try {
            QuerySnapshot snapshot = firestore.collection("audit_bootstrap")
                    .orderBy("timestamp", Query.Direction.DESCENDING)
                    .limit(1)
                    .get()
                    .get();

            if (!snapshot.isEmpty()) {
                return snapshot.getDocuments().get(0).getString("timestamp");
            }
        } catch (Exception e) {
            log.error("Failed to get last bootstrap attempt: {}", e.getMessage());
        }
        return "Unknown";
    }

    private String determineHealth(BootstrapHealthReport report) {
        if (report.criticalFailures > 0) {
            return "CRITICAL";
        }
        if (report.recentRollbacks > 3) {
            return "WARNING";
        }
        if (report.partialSaves > 0) {
            return "WARNING";
        }
        if (report.isComplete) {
            return "HEALTHY";
        }
        return "PENDING";
    }

    // Data classes for reports

    @Data
    public static class BootstrapHealthReport {
        private boolean isComplete;
        private int criticalFailures;
        private int recentRollbacks;
        private int partialSaves;
        private String lastAttempt;
        private String health;
    }

    @Data
    public static class CriticalFailure {
        private String id;
        private String timestamp;
        private String operation;
        private String originalError;
        private String rollbackError;
        private String failurePoint;
        private Map<String, Object> context;
    }

    /**
     * Gets email delivery failures (for diagnostics only - NO passwords).
     */
    public Mono<List<EmailFailure>> getEmailFailures() {
        return Mono.fromCallable(() -> {
            List<EmailFailure> failures = new ArrayList<>();

            try {
                QuerySnapshot snapshot = firestore.collection("audit_email_failures")
                        .orderBy("timestamp", Query.Direction.DESCENDING)
                        .limit(50)
                        .get()
                        .get();

                snapshot.getDocuments().forEach(doc -> {
                    EmailFailure failure = new EmailFailure();
                    failure.id = doc.getId();
                    failure.timestamp = doc.getString("timestamp");
                    failure.email = doc.getString("email");
                    failure.error = doc.getString("error");
                    failure.actionRequired = doc.getString("actionRequired");
                    failures.add(failure);
                });
            } catch (Exception e) {
                log.error("Failed to get email failures: {}", e.getMessage());
            }

            return failures;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @Data
    public static class EmailFailure {
        private String id;
        private String timestamp;
        private String email;
        private String error;
        private String actionRequired;
    }
    @Data
    public static class RollbackEvent {
        private String id;
        private String timestamp;
        private String operation;
        private String userId;
        private String error;
        private boolean cleaned;
    }

}
