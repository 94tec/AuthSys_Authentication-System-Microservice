package com.techStack.authSys.service.bootstrap;

import com.google.cloud.firestore.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Bootstrap Cleanup Service
 *
 * Cleans up orphaned data from failed bootstrap attempts.
 * Runs before the main bootstrap orchestrator.
 * Uses Clock for timestamp-based cleanup decisions.
 */
@Slf4j
@Component
@Order(1) // Run before BootstrapOrchestrator
@RequiredArgsConstructor
public class BootstrapCleanupService implements CommandLineRunner {

    /* =========================
       Dependencies
       ========================= */

    private final Firestore firestore;
    private final Clock clock;

    /* =========================
       Startup Execution
       ========================= */

    @Override
    public void run(String... args) {
        Instant startTime = clock.instant();

        log.info("🧹 Checking for orphaned bootstrap data at {}", startTime);

        cleanupOrphanedBootstrapData()
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(count -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    if (count > 0) {
                        log.warn("🧹 Cleaned up {} orphaned records in {} at {}",
                                count, duration, endTime);
                    } else {
                        log.info("✅ No orphaned bootstrap data found at {} (checked in {})",
                                endTime, duration);
                    }
                })
                .doOnError(e -> {
                    Instant endTime = clock.instant();
                    log.error("❌ Cleanup failed at {}: {}", endTime, e.getMessage(), e);
                })
                .subscribe();
    }

    /* =========================
       Cleanup Logic
       ========================= */

    /**
     * Identify and clean orphaned data from failed bootstrap attempts
     */
    private Mono<Integer> cleanupOrphanedBootstrapData() {
        Instant now = clock.instant();

        return Mono.fromCallable(() -> {
            int cleanedCount = 0;

            // Check for critical failures requiring manual intervention
            List<String> criticalFailures = checkCriticalFailures(now);
            if (!criticalFailures.isEmpty()) {
                log.error("🚨 Found {} critical failures at {} requiring manual review:",
                        criticalFailures.size(), now);
                criticalFailures.forEach(id -> log.error("   - Critical failure ID: {}", id));
            }

            // Check audit_rollbacks collection for recent failures
            List<RollbackRecord> recentRollbacks = getRecentRollbacks(now);

            for (RollbackRecord rollback : recentRollbacks) {
                try {
                    if (cleanupFromRollbackRecord(rollback, now)) {
                        cleanedCount++;
                    }
                } catch (Exception e) {
                    log.error("Failed to cleanup rollback {} at {}: {}",
                            rollback.userId, now, e.getMessage());
                }
            }

            // Check for partial saves
            List<String> partialSaves = checkPartialSaves(now);
            if (!partialSaves.isEmpty()) {
                log.warn("⚠️ Found {} partial saves at {} requiring manual cleanup:",
                        partialSaves.size(), now);
                partialSaves.forEach(id -> log.warn("   - Partial save ID: {}", id));
            }

            return cleanedCount;
        });
    }

    /* =========================
       Check Methods
       ========================= */

    /**
     * Check for critical failures logged during rollback
     */
    private List<String> checkCriticalFailures(Instant checkTime) {
        List<String> criticalIds = new ArrayList<>();

        try {
            QuerySnapshot snapshot = firestore.collection("audit_critical_failures")
                    .whereEqualTo("requiresManualCleanup", true)
                    .get()
                    .get();

            snapshot.getDocuments().forEach(doc -> criticalIds.add(doc.getId()));

            log.debug("Found {} critical failures at {}", criticalIds.size(), checkTime);

        } catch (Exception e) {
            log.error("Failed to check critical failures at {}: {}",
                    checkTime, e.getMessage());
        }

        return criticalIds;
    }

    /**
     * Get recent rollback records for cleanup
     */
    private List<RollbackRecord> getRecentRollbacks(Instant checkTime) {
        List<RollbackRecord> rollbacks = new ArrayList<>();

        try {
            // Get rollbacks from the last hour
            Instant oneHourAgo = checkTime.minus(1, ChronoUnit.HOURS);

            QuerySnapshot snapshot = firestore.collection("audit_rollbacks")
                    .whereEqualTo("operation", "SUPER_ADMIN_BOOTSTRAP")
                    .get()
                    .get();

            for (QueryDocumentSnapshot doc : snapshot.getDocuments()) {
                String userId = (String) doc.get("userId");
                String timestampStr = (String) doc.get("timestamp");

                // Only process recent rollbacks
                if (userId != null && timestampStr != null) {
                    try {
                        Instant rollbackTime = Instant.parse(timestampStr);
                        if (rollbackTime.isAfter(oneHourAgo)) {
                            RollbackRecord record = new RollbackRecord();
                            record.userId = userId;
                            record.timestamp = rollbackTime;
                            record.context = (java.util.Map<String, Object>) doc.get("context");
                            rollbacks.add(record);
                        }
                    } catch (Exception e) {
                        log.warn("Failed to parse rollback timestamp: {}", timestampStr);
                    }
                }
            }

            log.debug("Found {} recent rollbacks at {}", rollbacks.size(), checkTime);

        } catch (Exception e) {
            log.error("Failed to get recent rollbacks at {}: {}",
                    checkTime, e.getMessage());
        }

        return rollbacks;
    }

    /**
     * Check for partial saves requiring manual cleanup
     */
    private List<String> checkPartialSaves(Instant checkTime) {
        List<String> partialSaveIds = new ArrayList<>();

        try {
            QuerySnapshot snapshot = firestore.collection("audit_partial_saves")
                    .whereEqualTo("action", "REQUIRES_MANUAL_CLEANUP")
                    .get()
                    .get();

            snapshot.getDocuments().forEach(doc -> partialSaveIds.add(doc.getId()));

            log.debug("Found {} partial saves at {}", partialSaveIds.size(), checkTime);

        } catch (Exception e) {
            log.error("Failed to check partial saves at {}: {}",
                    checkTime, e.getMessage());
        }

        return partialSaveIds;
    }

    /* =========================
       Cleanup Execution
       ========================= */

    /**
     * Clean up data based on rollback record context
     */
    private boolean cleanupFromRollbackRecord(RollbackRecord rollback, Instant cleanupTime) {
        if (rollback.userId == null) {
            return false;
        }

        boolean cleaned = false;

        try {
            WriteBatch batch = firestore.batch();
            int operations = 0;

            // Check and clean user document
            DocumentReference userRef = firestore.collection("users")
                    .document(rollback.userId);
            if (documentExists(userRef)) {
                batch.delete(userRef);
                operations++;
                log.debug("🧹 Queued user document for deletion: {}", rollback.userId);
            }

            // Check and clean roles
            QuerySnapshot roleSnapshot = firestore.collection("user_roles")
                    .whereEqualTo("userId", rollback.userId)
                    .get()
                    .get();

            for (QueryDocumentSnapshot roleDoc : roleSnapshot.getDocuments()) {
                batch.delete(roleDoc.getReference());
                operations++;
            }
            if (!roleSnapshot.isEmpty()) {
                log.debug("🧹 Queued {} role documents for deletion", roleSnapshot.size());
            }

            // Check and clean permissions
            DocumentReference permRef = firestore.collection("user_permissions")
                    .document(rollback.userId);
            if (documentExists(permRef)) {
                batch.delete(permRef);
                operations++;
                log.debug("🧹 Queued permissions document for deletion");
            }

            // Execute batch if we have operations
            if (operations > 0) {
                batch.commit().get();
                log.info("✅ Cleaned up {} documents for user: {} at {}",
                        operations, rollback.userId, cleanupTime);
                cleaned = true;

                // Mark rollback record as processed
                firestore.collection("audit_rollbacks")
                        .document(rollback.userId)
                        .update(
                                "cleaned", true,
                                "cleanedAt", cleanupTime.toString()
                        )
                        .get();
            }

        } catch (Exception e) {
            log.error("Failed to cleanup user {} at {}: {}",
                    rollback.userId, cleanupTime, e.getMessage());
        }

        return cleaned;
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Check if a document exists
     */
    private boolean documentExists(DocumentReference ref) {
        try {
            DocumentSnapshot snapshot = ref.get().get();
            return snapshot.exists();
        } catch (Exception e) {
            return false;
        }
    }

    /* =========================
       Inner Classes
       ========================= */

    /**
     * Internal class to hold rollback record data
     */
    private static class RollbackRecord {
        String userId;
        Instant timestamp;
        java.util.Map<String, Object> context;
    }
}