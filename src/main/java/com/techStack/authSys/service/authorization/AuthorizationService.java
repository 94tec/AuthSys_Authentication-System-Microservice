package com.techStack.authSys.service.authorization;

import com.techStack.authSys.config.security.PermissionsConfig;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authorization Service
 *
 * Lightweight service for permission configuration management.
 * Delegates to PermissionService for actual permission operations.
 */
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final ConcurrentHashMap<Roles, Set<Permissions>> rolePermissions = new ConcurrentHashMap<>();
    private final PermissionsConfig permissionsConfig;
    private final PermissionService permissionService;

    @PostConstruct
    @Scheduled(fixedDelay = 30000) // Reload every 30 seconds
    public void reloadPermissions() {
        permissionsConfig.getRoles().forEach((role, perms) -> {
            Set<Permissions> permSet = ConcurrentHashMap.newKeySet(perms.size());
            permSet.addAll(perms);
            rolePermissions.put(role, permSet);
        });

        // Delegate to PermissionService for full reload
        permissionService.reloadPermissions();
    }
}