package com.techStack.authSys.authorization.yaml;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutures;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteResult;
import com.techStack.authSys.authorization.models.FirestorePermission;
import com.techStack.authSys.authorization.service.PermissionCacheWarmupService;
import com.techStack.authSys.config.cache.CacheConfig;
import com.techStack.authSys.authorization.models.Roles;
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

import static com.techStack.authSys.authorization.constants.SecurityConstants.VALID_NAMESPACES;

/**
 * Tour Permission Seeder
 *
 * Seeds Tour Management System permissions and role mappings
 * into Firestore during application startup.
 *
 * Sources:
 *   application.permissions
 *   application.role_permissions
 *
 * Example namespaces:
 *
 *   traveler
 *   booking
 *   enquire-button.tsx
 *   destination
 *   itinerary
 *   guide
 *   vehicle
 *   supplier
 *   payment
 *   review
 *   report
 *   user
 *   system
 *
 * Example permissions:
 *
 *   booking:create
 *   booking:approve
 *   enquire-button.tsx:create
 *   enquire-button.tsx:publish
 *   payment:refund
 *
 * Example role mappings:
 *
 *   USER
 *      booking:create
 *      booking:view_own
 *
 *   OPERATOR
 *      enquire-button.tsx:create
 *      enquire-button.tsx:update
 *
 *   MANAGER
 *      booking:approve
 *      guide:assign
 *
 * Startup will fail if permission seeding fails.
 * This prevents the application from running with
 * incomplete RBAC configuration.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PermissionSeeder implements ApplicationRunner {

    private final Firestore firestore;

    private final PermissionYamlLoader permissionsYamlLoader;
    private final SecurityBootstrapValidator validator;
    private final PermissionCacheWarmupService cacheWarmupService;
    private final CacheConfig cacheConfig;

    private static final String PERMISSIONS_COLLECTION =
            "permissions";

    private static final String ROLE_PERMISSIONS_COLLECTION =
            "role_permissions";

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

        log.info("▶ Starting RBAC initialization...");

        PermissionsYamlConfig config = permissionsYamlLoader.load();

        seed(config);

        validate(config);

        warmCache(config);

        log.info("✅ RBAC initialized successfully.");
    }
    private void seed(PermissionsYamlConfig config) throws Exception {
        if (!config.isSeedOnStartup()) {
            return;
        }

        int permissions = seedPermissions();
        int mappings = seedRolePermissions();

        log.info("Seeded {} permissions and {} role mappings.", permissions, mappings);
    }
    private void validate(PermissionsYamlConfig config) {
        if (!config.isValidateOnStartup()) {
            return;
        }

        validator.validate();
    }
    private void warmCache(PermissionsYamlConfig config) {
        if (!config.getCache().isWarmOnStartup()) {
            return;
        }

        cacheWarmupService.warmPermissions().block();
    }
    // -------------------------------------------------------------------------
    // Phase 1: seed permissions/{id}
    // -------------------------------------------------------------------------

    /**
     * Writes one document per permission to the permissions/ collection.
     *
     * Document ID uses FirestorePermission.toDocumentId():
     *
     * "enquire-button.tsx:publish"      → "tour__publish"
     * "booking:create"    → "booking__create"
     * "payment:refund"    → "payment__refund"
     *
     * Full set() is used — overwrites any stale description or category
     * from a previous YAML version.
     *
     * @return number of permission documents written
     * @throws Exception if any Firestore write fails or is interrupted
     */
    private int seedPermissions() throws Exception {
        PermissionsYamlConfig config = permissionsYamlLoader.load();

        if (config.getPermissions() == null || config.getPermissions().isEmpty()) {
            log.warn("⚠ No permissions defined in YAML — skipping permissions seed");
            return 0;
        }

        List<ApiFuture<WriteResult>> futures = new ArrayList<>();

        config.getPermissions().forEach((namespace, nsConfig) -> {
            if (!VALID_NAMESPACES.contains(namespace)) {
                log.warn(
                        "Unknown permission namespace '{}' found in YAML",
                        namespace
                );
            }

            if (nsConfig == null || nsConfig.getActions() == null) {
                log.warn(
                        "Namespace '{}' has null config or actions — skipping",
                        namespace
                );
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
                                "namespace", permission.getNamespace(),
                                "action", permission.getAction(),
                                "fullName", permission.getFullName(),
                                "description", permission.getDescription(),
                                "category", permission.getCategory(),
                                "active", true,
                                "seeded", true,
                                "version", 1
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
        Map<String, List<String>> allRolePermissions = permissionsYamlLoader.resolveAllRolePermissions();

        if (allRolePermissions.isEmpty()) {
            log.warn("⚠ No role permissions resolved from YAML — skipping role_permissions seed");
            return 0;
        }

        List<ApiFuture<WriteResult>> futures = new ArrayList<>();

        allRolePermissions.forEach((roleName, permissions) -> {
            Roles.fromName(roleName)
                    .orElseThrow(() ->
                            new IllegalStateException(
                                    "Unknown role in permissions.yaml: " + roleName
                            ));
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