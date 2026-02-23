package com.techStack.authSys.repository.authorization;

import com.google.cloud.firestore.Firestore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Repository for reading role → permission mappings from Firestore.
 *
 * Collection: role_permissions/{roleName}
 *
 * Example document (id: "ADMIN"):
 * {
 *   "permissions": ["portfolio:view", "portfolio:create", "user:read", ...]
 * }
 *
 * These documents are written once by PermissionSeeder at startup and are
 * effectively static for the lifetime of the application. They are cached
 * aggressively — cache is only evicted when PermissionSeeder re-seeds
 * (e.g. after a YAML change and redeploy).
 *
 * Blocking I/O note:
 *   Firestore's Java SDK is blocking. All reads are wrapped in
 *   Mono.fromCallable() and dispatched to Schedulers.boundedElastic()
 *   so they never block a Reactor event-loop thread. This is consistent
 *   with how PermissionService handles its Firestore reads.
 *
 * Null-safety:
 *   Firestore may return a document where the "permissions" field is
 *   absent (legacy document) or is an unexpected type. Both cases are
 *   handled gracefully — the caller receives an empty list rather than
 *   a NullPointerException or ClassCastException.
 */
@Repository
@RequiredArgsConstructor
@Slf4j
public class FirestoreRolePermissionsRepository {

    private final Firestore firestore;

    private static final String COLLECTION       = "role_permissions";
    private static final String PERMISSIONS_FIELD = "permissions";

    // -------------------------------------------------------------------------
    // Single role lookup
    // -------------------------------------------------------------------------

    /**
     * Returns all permission full names for a given role, reactively.
     *
     * Result is cached under "rolePermissions" keyed by roleName.
     * Cache is populated on first call per role and held until evicted
     * by {@link #evictCache()}.
     *
     * e.g. findByRoleName("ADMIN") → ["portfolio:view", "user:create", ...]
     *
     * @param roleName uppercase role name e.g. "ADMIN"
     * @return Mono emitting the permission list, or empty list if role not found
     */
    @Cacheable(value = "rolePermissions", key = "#roleName")
    public Mono<List<String>> findByRoleName(String roleName) {
        if (roleName == null || roleName.isBlank()) {
            log.warn("findByRoleName called with null or blank roleName");
            return Mono.just(Collections.emptyList());
        }

        return Mono.fromCallable(() -> {
                    var doc = firestore
                            .collection(COLLECTION)
                            .document(roleName)
                            .get()
                            .get(); // blocking — safe on boundedElastic

                    if (!doc.exists()) {
                        log.warn("No role_permissions document found for role: {}", roleName);
                        return Collections.<String>emptyList();
                    }

                    return extractPermissions(doc.getData(), roleName);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(perms ->
                        log.debug("Loaded {} permissions for role {}", perms.size(), roleName))
                .doOnError(e ->
                        log.error("Failed to fetch permissions for role {}: {}",
                                roleName, e.getMessage(), e))
                .onErrorReturn(Collections.emptyList());
    }

    /**
     * Blocking variant for use in non-reactive contexts only.
     *
     * Use this ONLY when you are already on a boundedElastic thread
     * (e.g. inside a Mono.fromCallable() block). Never call this from
     * a Reactor event-loop thread or from a @Cacheable-proxied reactive chain.
     *
     * Prefer {@link #findByRoleName(String)} in all reactive code paths.
     *
     * @param roleName uppercase role name e.g. "ADMIN"
     * @return permission list, or empty list if role not found
     */
    @Cacheable(value = "rolePermissions", key = "#roleName")
    public List<String> findByRoleNameBlocking(String roleName) {
        if (roleName == null || roleName.isBlank()) {
            log.warn("findByRoleNameBlocking called with null or blank roleName");
            return Collections.emptyList();
        }

        try {
            var doc = firestore
                    .collection(COLLECTION)
                    .document(roleName)
                    .get()
                    .get();

            if (!doc.exists()) {
                log.warn("No role_permissions document found for role: {}", roleName);
                return Collections.emptyList();
            }

            return extractPermissions(doc.getData(), roleName);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // restore interrupt flag
            log.error("Interrupted while fetching permissions for role {}", roleName, e);
            return Collections.emptyList();

        } catch (Exception e) {
            log.error("Failed to fetch permissions for role {}: {}", roleName, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    // -------------------------------------------------------------------------
    // Multi-role resolution
    // -------------------------------------------------------------------------

    /**
     * Resolves the union of permissions across multiple roles, reactively.
     *
     * Handles users with multiple roles — merges all permissions and
     * deduplicates. The caller (AuthService) then applies user-level
     * grants and denials on top of this resolved set.
     *
     * e.g. resolveForRoles(["ADMIN", "MANAGER"])
     *        → union of ADMIN permissions + MANAGER permissions, deduplicated
     *
     * @param roleNames list of uppercase role names
     * @return Mono emitting the deduplicated merged permission list
     */
    public Mono<List<String>> resolveForRoles(List<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) {
            log.debug("resolveForRoles called with empty role list — returning empty");
            return Mono.just(Collections.emptyList());
        }

        return Flux.fromIterable(roleNames)
                .flatMap(this::findByRoleName)
                .flatMap(Flux::fromIterable)
                .distinct()
                .collectList()
                .doOnSuccess(perms ->
                        log.debug("Resolved {} total permissions for roles {}",
                                perms.size(), roleNames));
    }

    /**
     * Blocking variant of resolveForRoles for non-reactive contexts.
     *
     * Same caveats as {@link #findByRoleNameBlocking(String)} — only use
     * when already executing on a boundedElastic thread.
     *
     * @param roleNames list of uppercase role names
     * @return deduplicated merged permission list
     */
    public List<String> resolveForRolesBlocking(List<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) {
            return Collections.emptyList();
        }

        return roleNames.stream()
                .flatMap(role -> findByRoleNameBlocking(role).stream())
                .distinct()
                .toList();
    }

    // -------------------------------------------------------------------------
    // Cache management
    // -------------------------------------------------------------------------

    /**
     * Evicts all cached role permission entries.
     *
     * Call this after PermissionSeeder re-seeds role_permissions in Firestore
     * so that the next login picks up the updated permission sets.
     */
    @CacheEvict(value = "rolePermissions", allEntries = true)
    public void evictCache() {
        log.info("Role permissions cache evicted — next reads will reload from Firestore");
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Safely extracts the "permissions" field from a Firestore document's data map.
     *
     * Guards against:
     *   - Null data map (document exists but has no fields)
     *   - Missing "permissions" field (legacy document written before this field existed)
     *   - Wrong type (field exists but is not a List — corrupt document)
     *
     * @param data     raw Firestore document data map, may be null
     * @param roleName role name used only for logging
     * @return list of permission strings, never null
     */
    @SuppressWarnings("unchecked")
    private List<String> extractPermissions(Map<String, Object> data, String roleName) {
        if (data == null) {
            log.warn("role_permissions document for {} has null data map", roleName);
            return Collections.emptyList();
        }

        Object raw = data.get(PERMISSIONS_FIELD);

        if (raw == null) {
            log.warn("role_permissions document for {} is missing '{}' field",
                    roleName, PERMISSIONS_FIELD);
            return Collections.emptyList();
        }

        if (!(raw instanceof List<?>)) {
            log.error("role_permissions document for {} has unexpected type for '{}': {}",
                    roleName, PERMISSIONS_FIELD, raw.getClass().getName());
            return Collections.emptyList();
        }

        List<?> rawList = (List<?>) raw;

        // Filter out any non-String entries that may have crept in via a bad write
        List<String> permissions = rawList.stream()
                .filter(item -> item instanceof String)
                .map(item -> (String) item)
                .filter(item -> !item.isBlank())
                .toList();

        if (permissions.size() != rawList.size()) {
            log.warn("role_permissions for {} had {} non-String or blank entries that were filtered out",
                    roleName, rawList.size() - permissions.size());
        }

        return permissions;
    }
}