package com.techStack.authSys.config.yaml;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutures;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteResult;
import com.techStack.authSys.models.firestore.FirestorePermission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Permission Seeder
 *
 * Writes permissions and role_permissions to Firestore at application startup,
 * based on the contents of permissions.yaml (bound via PermissionsYamlConfig).
 *
 * This runs once per startup. It is idempotent — re-seeding overwrites existing
 * documents with the current YAML state, which is the desired behaviour after
 * a permission schema change.
 *
 * Execution order:
 *   1. seedPermissions()      — writes permissions/{id} documents
 *   2. seedRolePermissions()  — writes role_permissions/{roleName} documents
 *
 * Both phases complete fully before run() returns, so any service that reads
 * from Firestore at startup is guaranteed to see the seeded data.
 *
 * Fire-and-forget fix:
 *   The original used addListener() with Runnable::run and discarded the
 *   ApiFuture<WriteResult>. This meant run() returned before any write
 *   completed, leaving Firestore empty for the duration of startup.
 *   We now collect all ApiFutures and call ApiFutures.allAsList(...).get()
 *   to block until every write has been acknowledged by Firestore.
 *
 * Save strategy:
 *   We use set() WITHOUT SetOptions.merge() for role_permissions documents.
 *   Merge cannot remove stale permissions from the list — a full set() is
 *   required to ensure the Firestore state matches the YAML exactly.
 *   For permissions/{id} documents we also use full set() so that
 *   description/category changes in YAML are reflected in Firestore.
 *
 * Document ID scheme:
 *   Uses FirestorePermission.toDocumentId() which produces double-underscore
 *   separated IDs ("portfolio__publish") to avoid ambiguity with snake_case
 *   action names. See FirestorePermission for full rationale.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PermissionSeeder implements ApplicationRunner {

    private final Firestore firestore;
    private final PermissionYamlLoader yamlLoader;

    private static final String PERMISSIONS_COLLECTION      = "permissions";
    private static final String ROLE_PERMISSIONS_COLLECTION = "role_permissions";

    // Executor for ApiFutures callbacks — keeps listener threads off the main thread
    private static final Executor CALLBACK_EXECUTOR =
            Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "seeder-callback");
                t.setDaemon(true);
                return t;
            });

    // -------------------------------------------------------------------------
    // ApplicationRunner entry point
    // -------------------------------------------------------------------------

    /**
     * Seeds permissions then role_permissions, blocking until both complete.
     *
     * Any write failure throws and aborts startup — a misconfigured permission
     * schema should be a hard startup failure, not a silent data gap.
     */
    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("▶ PermissionSeeder starting...");

        int permCount = seedPermissions();
        int roleCount = seedRolePermissions();

        log.info("✅ PermissionSeeder complete — {} permissions, {} role mappings seeded",
                permCount, roleCount);
    }

    // -------------------------------------------------------------------------
    // Phase 1: seed permissions/{id}
    // -------------------------------------------------------------------------

    /**
     * Writes one document per permission to the permissions/ collection.
     *
     * Document ID uses FirestorePermission.toDocumentId():
     *   "portfolio:publish" → "portfolio__publish"
     *
     * Full set() is used — overwrites any stale description or category
     * from a previous YAML version.
     *
     * @return number of permission documents written
     * @throws Exception if any Firestore write fails or is interrupted
     */
    private int seedPermissions() throws Exception {
        PermissionsYamlConfig config = yamlLoader.load();

        if (config.getPermissions() == null || config.getPermissions().isEmpty()) {
            log.warn("⚠ No permissions defined in YAML — skipping permissions seed");
            return 0;
        }

        List<ApiFuture<WriteResult>> futures = new ArrayList<>();

        config.getPermissions().forEach((namespace, nsConfig) -> {
            if (nsConfig == null || nsConfig.getActions() == null) {
                log.warn("Namespace '{}' has null config or actions — skipping", namespace);
                return;
            }

            nsConfig.getActions().forEach(actionConfig -> {
                if (actionConfig == null
                        || actionConfig.getAction() == null
                        || actionConfig.getAction().isBlank()) {
                    log.warn("Namespace '{}' has a null/blank action entry — skipping", namespace);
                    return;
                }

                // Use the factory — derives id, fullName, and all fields consistently
                FirestorePermission permission = FirestorePermission.of(
                        namespace,
                        actionConfig.getAction(),
                        actionConfig.getDescription() != null
                                ? actionConfig.getDescription()
                                : "",
                        nsConfig.getCategory() != null
                                ? nsConfig.getCategory()
                                : namespace.toUpperCase()
                );

                // Full set() — not merge — so description/category updates land correctly
                ApiFuture<WriteResult> future = firestore
                        .collection(PERMISSIONS_COLLECTION)
                        .document(permission.getId())
                        .set(Map.of(
                                "namespace",   permission.getNamespace(),
                                "action",      permission.getAction(),
                                "fullName",    permission.getFullName(),
                                "description", permission.getDescription(),
                                "category",    permission.getCategory()
                        ));

                futures.add(future);
                log.debug("Queued permission write: {} → {}", permission.getId(),
                        permission.getFullName());
            });
        });

        // Block until ALL writes are acknowledged — no fire-and-forget
        awaitAll(futures, "permissions");

        log.info("✅ Seeded {} permission documents", futures.size());
        return futures.size();
    }

    // -------------------------------------------------------------------------
    // Phase 2: seed role_permissions/{roleName}
    // -------------------------------------------------------------------------

    /**
     * Writes one document per role to the role_permissions/ collection.
     *
     * Uses resolveAllRolePermissions() which expands wildcards ("*:*",
     * "portfolio:*") into concrete permission full names before writing.
     *
     * Full set() is used — overwrites the permissions list entirely so
     * removed permissions don't linger from a previous YAML version.
     *
     * @return number of role_permissions documents written
     * @throws Exception if any Firestore write fails or is interrupted
     */
    private int seedRolePermissions() throws Exception {
        // resolveAllRolePermissions() handles wildcard expansion and null guards
        Map<String, List<String>> allRolePermissions = yamlLoader.resolveAllRolePermissions();

        if (allRolePermissions.isEmpty()) {
            log.warn("⚠ No role permissions resolved from YAML — skipping role_permissions seed");
            return 0;
        }

        List<ApiFuture<WriteResult>> futures = new ArrayList<>();

        allRolePermissions.forEach((roleName, permissions) -> {
            // Full set() — not merge — so stale permissions are overwritten
            ApiFuture<WriteResult> future = firestore
                    .collection(ROLE_PERMISSIONS_COLLECTION)
                    .document(roleName)
                    .set(Map.of("permissions", permissions));

            futures.add(future);
            log.debug("Queued role_permissions write: {} → {} permissions",
                    roleName, permissions.size());
        });

        // Block until ALL writes are acknowledged
        awaitAll(futures, "role_permissions");

        allRolePermissions.forEach((roleName, permissions) ->
                log.info("✅ Seeded role '{}' with {} permissions", roleName, permissions.size()));

        return futures.size();
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Blocks until all ApiFutures complete, throwing on any failure.
     *
     * ApiFutures.allAsList() returns a single future that succeeds only
     * when ALL constituent futures succeed, and fails fast on the first
     * error. This guarantees run() does not return until Firestore has
     * acknowledged every write.
     *
     * @param futures     list of write futures to await
     * @param contextName used only for log messages e.g. "permissions"
     * @throws Exception if any write fails or the thread is interrupted
     */
    private void awaitAll(
            List<ApiFuture<WriteResult>> futures,
            String contextName
    ) throws Exception {
        if (futures.isEmpty()) {
            return;
        }

        try {
            // allAsList fails fast on first error — acceptable for seeding
            ApiFutures.allAsList(futures).get();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // restore interrupt flag
            throw new RuntimeException(
                    "PermissionSeeder interrupted while awaiting " + contextName + " writes", e);

        } catch (Exception e) {
            throw new RuntimeException(
                    "PermissionSeeder failed during " + contextName + " phase: " + e.getMessage(),
                    e);
        }
    }
}