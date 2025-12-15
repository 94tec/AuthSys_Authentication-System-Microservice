package com.techStack.authSys.service.bootstrap;

import com.google.cloud.firestore.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * Cleans up orphaned data from failed bootstrap attempts.
 * Runs before the main bootstrap orchestrator.
 */
@Slf4j
@Component
@Order(1) // Run before BootstrapOrchestrator
@RequiredArgsConstructor
public class BootstrapCleanupService implements CommandLineRunner {

    private final Firestore firestore;

    @Override
    public void run(String... args) {
        log.info("🧹 Checking for orphaned bootstrap data...");

        cleanupOrphanedBootstrapData()
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(count -> {
                    if (count > 0) {
                        log.warn("🧹 Cleaned up {} orphaned records from failed bootstraps", count);
                    } else {
                        log.info("✅ No orphaned bootstrap data found");
                    }
                })
                .doOnError(e -> log.error("❌ Cleanup failed: {}", e.getMessage(), e))
                .subscribe();
    }

    /**
     * Identifies and cleans orphaned data from failed bootstrap attempts.
     */
    private Mono<Integer> cleanupOrphanedBootstrapData() {
        return Mono.fromCallable(() -> {
            int cleanedCount = 0;

            // Check for critical failures requiring manual intervention
            List<String> criticalFailures = checkCriticalFailures();
            if (!criticalFailures.isEmpty()) {
                log.error("🚨 Found {} critical failures requiring manual review:",
                        criticalFailures.size());
                criticalFailures.forEach(id -> log.error("   - Critical failure ID: {}", id));
            }

            // Check audit_rollbacks collection for recent failures
            List<RollbackRecord> recentRollbacks = getRecentRollbacks();

            for (RollbackRecord rollback : recentRollbacks) {
                try {
                    if (cleanupFromRollbackRecord(rollback)) {
                        cleanedCount++;
                    }
                } catch (Exception e) {
                    log.error("Failed to cleanup rollback {}: {}",
                            rollback.userId, e.getMessage());
                }
            }

            // Check for partial saves
            List<String> partialSaves = checkPartialSaves();
            if (!partialSaves.isEmpty()) {
                log.warn("⚠️ Found {} partial saves requiring manual cleanup:",
                        partialSaves.size());
                partialSaves.forEach(id -> log.warn("   - Partial save ID: {}", id));
            }

            return cleanedCount;
        });
    }

    /**
     * Checks for critical failures logged during rollback.
     */
    private List<String> checkCriticalFailures() {
        List<String> criticalIds = new ArrayList<>();

        try {
            QuerySnapshot snapshot = firestore.collection("audit_critical_failures")
                    .whereEqualTo("requiresManualCleanup", true)
                    .get()
                    .get();

            snapshot.getDocuments().forEach(doc -> criticalIds.add(doc.getId()));
        } catch (Exception e) {
            log.error("Failed to check critical failures: {}", e.getMessage());
        }

        return criticalIds;
    }

    /**
     * Gets recent rollback records for cleanup.
     */
    private List<RollbackRecord> getRecentRollbacks() {
        List<RollbackRecord> rollbacks = new ArrayList<>();

        try {
            // Get rollbacks from the last hour
            Instant oneHourAgo = Instant.now().minus(1, ChronoUnit.HOURS);

            QuerySnapshot snapshot = firestore.collection("audit_rollbacks")
                    .whereEqualTo("operation", "SUPER_ADMIN_BOOTSTRAP")
                    .get()
                    .get();

            for (QueryDocumentSnapshot doc : snapshot.getDocuments()) {
                String userId = (String) doc.get("userId");
                if (userId != null) {
                    RollbackRecord record = new RollbackRecord();
                    record.userId = userId;
                    record.context = (java.util.Map<String, Object>) doc.get("context");
                    rollbacks.add(record);
                }
            }
        } catch (Exception e) {
            log.error("Failed to get recent rollbacks: {}", e.getMessage());
        }

        return rollbacks;
    }

    /**
     * Cleans up data based on rollback record context.
     */
    private boolean cleanupFromRollbackRecord(RollbackRecord rollback) {
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
                log.info("✅ Cleaned up {} documents for user: {}", operations, rollback.userId);
                cleaned = true;

                // Mark rollback record as processed
                firestore.collection("audit_rollbacks")
                        .document(rollback.userId)
                        .update("cleaned", true, "cleanedAt", Instant.now().toString())
                        .get();
            }

        } catch (Exception e) {
            log.error("Failed to cleanup user {}: {}", rollback.userId, e.getMessage());
        }

        return cleaned;
    }

    /**
     * Checks if a document exists.
     */
    private boolean documentExists(DocumentReference ref) {
        try {
            DocumentSnapshot snapshot = ref.get().get();
            return snapshot.exists();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Checks for partial saves requiring manual cleanup.
     */
    private List<String> checkPartialSaves() {
        List<String> partialSaveIds = new ArrayList<>();

        try {
            QuerySnapshot snapshot = firestore.collection("audit_partial_saves")
                    .whereEqualTo("action", "REQUIRES_MANUAL_CLEANUP")
                    .get()
                    .get();

            snapshot.getDocuments().forEach(doc -> partialSaveIds.add(doc.getId()));
        } catch (Exception e) {
            log.error("Failed to check partial saves: {}", e.getMessage());
        }

        return partialSaveIds;
    }

    /**
     * Internal class to hold rollback record data.
     */
    private static class RollbackRecord {
        String userId;
        java.util.Map<String, Object> context;
    }
}
