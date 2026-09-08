package com.techStack.authSys.auth.service.bootstrap;

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

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Bootstrap Monitoring Service
 *
 * Provides health, diagnostics and operational statistics
 * for the bootstrap process.
 *
 * Firestore is used as the source of historical audit information.
 * Micrometer metrics remain responsible for application metrics.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapMonitoringService {

    private final Firestore firestore;
    private final BootstrapStateService stateService;
    private final Clock clock;

    /* =========================================================
       PUBLIC HEALTH API
       ========================================================= */

    /**
     * Gets comprehensive bootstrap health status.
     *
     * This response is intentionally shaped for the frontend:
     *
     * {
     *   bootstrapComplete,
     *   totalAttempts,
     *   successfulAttempts,
     *   failedAttempts,
     *   emailDeliveryRate,
     *   criticalFailures,
     *   recentRollbacks,
     *   partialSaves,
     *   lastBootstrapAt,
     *   health
     * }
     */
    public Mono<BootstrapHealthReport> getBootstrapHealth() {

        return Mono.fromCallable(() -> {

            Instant now = clock.instant();

            BootstrapHealthReport report =
                    new BootstrapHealthReport();

            /* -------------------------------------------------
               Bootstrap state
               ------------------------------------------------- */

            try {
                report.bootstrapComplete =
                        Boolean.TRUE.equals(
                                stateService.isBootstrapCompleted().block()
                        );
            } catch (Exception e) {
                log.warn(
                        "Unable to determine bootstrap state: {}",
                        e.getMessage()
                );

                report.bootstrapComplete = false;
            }

            /* -------------------------------------------------
               Historical bootstrap statistics
               ------------------------------------------------- */

            report.totalAttempts = countBootstrapAttempts();

            report.successfulAttempts =
                    countBootstrapEvents("SUCCESS");

            report.failedAttempts =
                    countBootstrapEvents("FAILURE");

            /* -------------------------------------------------
               Email statistics
               ------------------------------------------------- */

            report.emailDeliveryRate =
                    calculateEmailDeliveryRate();

            /* -------------------------------------------------
               Operational problems
               ------------------------------------------------- */

            report.criticalFailures =
                    countCriticalFailures();

            report.recentRollbacks =
                    countRecentRollbacks(24);

            report.partialSaves =
                    countPartialSaves();

            /* -------------------------------------------------
               Last bootstrap activity
               ------------------------------------------------- */

            report.lastBootstrapAt =
                    getLastBootstrapAttempt();

            /* -------------------------------------------------
               Overall health
               ------------------------------------------------- */

            report.health =
                    determineHealth(report);

            report.checkedAt = now.toString();

            log.debug(
                    "Bootstrap health calculated: {}",
                    report
            );

            return report;

        }).subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================================================
       BOOTSTRAP STATISTICS
       ========================================================= */

    /**
     * Counts bootstrap attempts.
     *
     * Supported event names:
     *
     * BOOTSTRAP_ATTEMPT
     * ATTEMPT
     *
     * If older audit records don't contain "event",
     * they are ignored rather than causing the endpoint to fail.
     */
    private int countBootstrapAttempts() {

        try {

            QuerySnapshot snapshot =
                    firestore.collection("audit_bootstrap")
                            .get()
                            .get();

            long count = snapshot.getDocuments()
                    .stream()
                    .filter(doc -> {

                        String event =
                                doc.getString("event");

                        if (event == null) {
                            return false;
                        }

                        return "BOOTSTRAP_ATTEMPT"
                                .equalsIgnoreCase(event)
                                || "ATTEMPT"
                                .equalsIgnoreCase(event);

                    })
                    .count();

            return safeInt(count);

        } catch (Exception e) {

            log.error(
                    "Failed to count bootstrap attempts: {}",
                    e.getMessage()
            );

            return 0;
        }
    }

    /**
     * Counts successful or failed bootstrap events.
     */
    private int countBootstrapEvents(String eventType) {

        try {

            QuerySnapshot snapshot =
                    firestore.collection("audit_bootstrap")
                            .get()
                            .get();

            long count = snapshot.getDocuments()
                    .stream()
                    .filter(doc -> {

                        String event =
                                doc.getString("event");

                        if (event == null) {
                            return false;
                        }

                        if ("SUCCESS".equalsIgnoreCase(eventType)) {

                            return "BOOTSTRAP_SUCCESS"
                                    .equalsIgnoreCase(event)
                                    || "SUCCESS"
                                    .equalsIgnoreCase(event);

                        }

                        if ("FAILURE".equalsIgnoreCase(eventType)) {

                            return "BOOTSTRAP_FAILURE"
                                    .equalsIgnoreCase(event)
                                    || "FAILURE"
                                    .equalsIgnoreCase(event);

                        }

                        return false;

                    })
                    .count();

            return safeInt(count);

        } catch (Exception e) {

            log.error(
                    "Failed to count bootstrap {} events: {}",
                    eventType,
                    e.getMessage()
            );

            return 0;
        }
    }

    /* =========================================================
       EMAIL DELIVERY
       ========================================================= */

    /**
     * Calculates email delivery percentage.
     *
     * Formula:
     *
     * successful emails
     * ----------------- × 100
     * total email attempts
     *
     * If there have been no email attempts, the result is 0.
     */
    private double calculateEmailDeliveryRate() {

        try {

            QuerySnapshot snapshot =
                    firestore.collection("audit_bootstrap")
                            .get()
                            .get();

            long emailSuccess =
                    snapshot.getDocuments()
                            .stream()
                            .filter(doc ->
                                    isEvent(
                                            doc,
                                            "EMAIL_SUCCESS"
                                    )
                            )
                            .count();

            long emailFailure =
                    snapshot.getDocuments()
                            .stream()
                            .filter(doc ->
                                    isEvent(
                                            doc,
                                            "EMAIL_FAILURE"
                                    )
                            )
                            .count();

            long total =
                    emailSuccess + emailFailure;

            if (total == 0) {
                return 0.0;
            }

            double rate =
                    ((double) emailSuccess / total) * 100.0;

            return round(rate, 2);

        } catch (Exception e) {

            log.error(
                    "Failed to calculate email delivery rate: {}",
                    e.getMessage()
            );

            return 0.0;
        }
    }

    private boolean isEvent(
            com.google.cloud.firestore.QueryDocumentSnapshot doc,
            String expectedEvent) {

        String event =
                doc.getString("event");

        return event != null
                && expectedEvent.equalsIgnoreCase(event);
    }

    /* =========================================================
       CRITICAL FAILURES
       ========================================================= */

    /**
     * Gets all critical failures requiring manual intervention.
     */
    public Mono<List<CriticalFailure>> getCriticalFailures() {

        return Mono.fromCallable(() -> {

            List<CriticalFailure> failures =
                    new ArrayList<>();

            try {

                QuerySnapshot snapshot =
                        firestore.collection(
                                        "audit_critical_failures"
                                )
                                .whereEqualTo(
                                        "requiresManualCleanup",
                                        true
                                )
                                .limit(50)
                                .get()
                                .get();

                snapshot.getDocuments()
                        .forEach(doc -> {

                            CriticalFailure failure =
                                    new CriticalFailure();

                            failure.id = doc.getId();
                            failure.timestamp =
                                    doc.getString("timestamp");

                            failure.operation =
                                    doc.getString("operation");

                            failure.originalError =
                                    doc.getString("originalError");

                            failure.rollbackError =
                                    doc.getString("rollbackError");

                            failure.failurePoint =
                                    doc.getString("failurePoint");

                            failure.context =
                                    getMap(doc.get("context"));

                            failures.add(failure);
                        });

            } catch (Exception e) {

                log.error(
                        "Failed to get critical failures: {}",
                        e.getMessage()
                );
            }

            return failures;

        }).subscribeOn(Schedulers.boundedElastic());
    }

    private int countCriticalFailures() {

        try {

            AggregateQuerySnapshot snapshot =
                    firestore.collection(
                                    "audit_critical_failures"
                            )
                            .whereEqualTo(
                                    "requiresManualCleanup",
                                    true
                            )
                            .count()
                            .get()
                            .get();

            return safeInt(snapshot.getCount());

        } catch (Exception e) {

            log.error(
                    "Failed to count critical failures: {}",
                    e.getMessage()
            );

            return 0;
        }
    }

    /* =========================================================
       ROLLBACKS
       ========================================================= */

    /**
     * Gets recent rollback events.
     */
    public Mono<List<RollbackEvent>> getRecentRollbacks(
            int hours) {

        return Mono.fromCallable(() -> {

            List<RollbackEvent> rollbacks =
                    new ArrayList<>();

            try {

                QuerySnapshot snapshot =
                        firestore.collection("audit_rollbacks")
                                .orderBy(
                                        "timestamp",
                                        Query.Direction.DESCENDING
                                )
                                .limit(100)
                                .get()
                                .get();

                Instant cutoff =
                        clock.instant()
                                .minus(hours, ChronoUnit.HOURS);

                snapshot.getDocuments()
                        .forEach(doc -> {

                            String timestampStr =
                                    doc.getString("timestamp");

                            if (timestampStr == null) {
                                return;
                            }

                            try {

                                Instant timestamp =
                                        Instant.parse(timestampStr);

                                if (timestamp.isAfter(cutoff)) {

                                    RollbackEvent event =
                                            new RollbackEvent();

                                    event.id = doc.getId();

                                    event.timestamp =
                                            timestampStr;

                                    event.operation =
                                            doc.getString(
                                                    "operation"
                                            );

                                    event.userId =
                                            doc.getString(
                                                    "userId"
                                            );

                                    event.error =
                                            doc.getString("error");

                                    event.cleaned =
                                            Boolean.TRUE.equals(
                                                    doc.getBoolean(
                                                            "cleaned"
                                                    )
                                            );

                                    rollbacks.add(event);
                                }

                            } catch (Exception e) {

                                log.warn(
                                        "Invalid rollback timestamp: {}",
                                        timestampStr
                                );
                            }

                        });

            } catch (Exception e) {

                log.error(
                        "Failed to get recent rollbacks: {}",
                        e.getMessage()
                );
            }

            return rollbacks;

        }).subscribeOn(Schedulers.boundedElastic());
    }

    private int countRecentRollbacks(int hours) {

        try {

            Instant cutoff =
                    clock.instant()
                            .minus(hours, ChronoUnit.HOURS);

            QuerySnapshot snapshot =
                    firestore.collection("audit_rollbacks")
                            .get()
                            .get();

            long count =
                    snapshot.getDocuments()
                            .stream()
                            .filter(doc -> {

                                String timestamp =
                                        doc.getString("timestamp");

                                if (timestamp == null) {
                                    return false;
                                }

                                try {

                                    return Instant.parse(
                                            timestamp
                                    ).isAfter(cutoff);

                                } catch (Exception e) {

                                    return false;
                                }

                            })
                            .count();

            return safeInt(count);

        } catch (Exception e) {

            log.error(
                    "Failed to count recent rollbacks: {}",
                    e.getMessage()
            );

            return 0;
        }
    }

    /* =========================================================
       PARTIAL SAVES
       ========================================================= */

    private int countPartialSaves() {

        try {

            AggregateQuerySnapshot snapshot =
                    firestore.collection(
                                    "audit_partial_saves"
                            )
                            .whereEqualTo(
                                    "action",
                                    "REQUIRES_MANUAL_CLEANUP"
                            )
                            .count()
                            .get()
                            .get();

            return safeInt(snapshot.getCount());

        } catch (Exception e) {

            log.error(
                    "Failed to count partial saves: {}",
                    e.getMessage()
            );

            return 0;
        }
    }

    /* =========================================================
       LAST BOOTSTRAP
       ========================================================= */

    private String getLastBootstrapAttempt() {

        try {

            QuerySnapshot snapshot =
                    firestore.collection("audit_bootstrap")
                            .orderBy(
                                    "timestamp",
                                    Query.Direction.DESCENDING
                            )
                            .limit(1)
                            .get()
                            .get();

            if (!snapshot.isEmpty()) {

                String timestamp =
                        snapshot.getDocuments()
                                .get(0)
                                .getString("timestamp");

                if (timestamp != null) {
                    return timestamp;
                }
            }

        } catch (Exception e) {

            log.error(
                    "Failed to get last bootstrap attempt: {}",
                    e.getMessage()
            );
        }

        return null;
    }

    /* =========================================================
       HEALTH CALCULATION
       ========================================================= */

    private String determineHealth(
            BootstrapHealthReport report) {

        /*
         * CRITICAL
         *
         * Manual intervention is required.
         */
        if (report.criticalFailures > 0) {
            return "CRITICAL";
        }

        /*
         * WARNING
         *
         * Partial data or repeated rollbacks.
         */
        if (report.partialSaves > 0) {
            return "WARNING";
        }

        if (report.recentRollbacks > 3) {
            return "WARNING";
        }

        /*
         * HEALTHY
         */
        if (report.bootstrapComplete) {
            return "HEALTHY";
        }

        /*
         * No successful bootstrap yet.
         */
        if (report.totalAttempts == 0) {
            return "PENDING";
        }

        /*
         * Attempts exist but bootstrap isn't complete.
         */
        if (report.failedAttempts > 0) {
            return "WARNING";
        }

        return "PENDING";
    }

    /* =========================================================
       MARK CRITICAL FAILURE RESOLVED
       ========================================================= */

    public Mono<Void> markCriticalFailureResolved(
            String failureId,
            String resolution) {

        return Mono.fromRunnable(() -> {

            try {

                firestore.collection(
                                "audit_critical_failures"
                        )
                        .document(failureId)
                        .update(
                                "requiresManualCleanup",
                                false,

                                "resolved",
                                true,

                                "resolvedAt",
                                clock.instant().toString(),

                                "resolution",
                                resolution
                        )
                        .get();

                log.info(
                        "✅ Marked critical failure as resolved: {}",
                        failureId
                );

            } catch (Exception e) {

                log.error(
                        "Failed to mark failure as resolved: {}",
                        e.getMessage()
                );
            }

        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /* =========================================================
       EMAIL FAILURE DIAGNOSTICS
       ========================================================= */

    /**
     * Gets email delivery failures.
     *
     * IMPORTANT:
     * This endpoint intentionally never exposes passwords.
     */
    public Mono<List<EmailFailure>> getEmailFailures() {

        return Mono.fromCallable(() -> {

            List<EmailFailure> failures =
                    new ArrayList<>();

            try {

                QuerySnapshot snapshot =
                        firestore.collection(
                                        "audit_email_failures"
                                )
                                .orderBy(
                                        "timestamp",
                                        Query.Direction.DESCENDING
                                )
                                .limit(50)
                                .get()
                                .get();

                snapshot.getDocuments()
                        .forEach(doc -> {

                            EmailFailure failure =
                                    new EmailFailure();

                            failure.id =
                                    doc.getId();

                            failure.timestamp =
                                    doc.getString("timestamp");

                            failure.email =
                                    doc.getString("email");

                            failure.error =
                                    doc.getString("error");

                            failure.actionRequired =
                                    doc.getString(
                                            "actionRequired"
                                    );

                            failures.add(failure);
                        });

            } catch (Exception e) {

                log.error(
                        "Failed to get email failures: {}",
                        e.getMessage()
                );
            }

            return failures;

        }).subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================================================
       HELPERS
       ========================================================= */

    @SuppressWarnings("unchecked")
    private Map<String, Object> getMap(Object value) {

        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }

        return null;
    }

    private int safeInt(long value) {

        if (value <= 0) {
            return 0;
        }

        if (value > Integer.MAX_VALUE) {
            return Integer.MAX_VALUE;
        }

        return (int) value;
    }

    private double round(
            double value,
            int decimalPlaces) {

        double multiplier =
                Math.pow(10, decimalPlaces);

        return Math.round(
                value * multiplier
        ) / multiplier;
    }

    /* =========================================================
       DATA CLASSES
       ========================================================= */

    @Data
    public static class BootstrapHealthReport {

        /*
         * Explicit name instead of "isComplete"
         * so the JSON contract is predictable.
         */
        private boolean bootstrapComplete;

        private int totalAttempts;

        private int successfulAttempts;

        private int failedAttempts;

        /*
         * Always initialized to a number.
         * Never null.
         */
        private double emailDeliveryRate = 0.0;

        private int criticalFailures;

        private int recentRollbacks;

        private int partialSaves;

        private String lastBootstrapAt;

        private String health;

        private String checkedAt;
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

    @Data
    public static class RollbackEvent {

        private String id;

        private String timestamp;

        private String operation;

        private String userId;

        private String error;

        private boolean cleaned;
    }

    @Data
    public static class EmailFailure {

        private String id;

        private String timestamp;

        private String email;

        private String error;

        private String actionRequired;
    }
}