package com.techStack.authSys.service.authorization;

import com.techStack.authSys.repository.authorization.PermissionProvider;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Authorization Service
 *
 * Lightweight service for permission configuration management.
 * Delegates entirely to PermissionService for permission operations.
 *
 * The old in-memory ConcurrentHashMap<Roles, Set<Permissions>> cache
 * and direct PermissionsConfig dependency are removed — PermissionService
 * now owns all permission state via Firestore-backed repositories.
 */
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final PermissionProvider permissionProvider;

    /**
     * Eagerly warms the permission caches on startup by triggering
     * a full reload from Firestore after PermissionSeeder has written data.
     *
     * Separated from the @Scheduled method — @PostConstruct and @Scheduled
     * must not share a method because @PostConstruct fires during bean
     * initialization (before the scheduler is active), while @Scheduled
     * fires on the scheduler's thread pool.
     */
    @PostConstruct
    public void initPermissions() {
        permissionProvider.reloadPermissions();
    }

    /**
     * Periodically evicts and reloads all permission caches from Firestore.
     *
     * Useful when permissions.yaml is re-seeded at runtime without a full
     * application restart (e.g. via an admin endpoint that calls
     * PermissionSeeder manually).
     *
     * Fixed delay of 30 s — adjust via application properties if needed.
     */
    @Scheduled(fixedDelayString = "${app.permissions.reload-interval-ms:30000}")
    public void reloadPermissions() {
        permissionProvider.reloadPermissions();
    }
}