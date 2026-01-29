package com.techStack.authSys.service.authorization;

import com.techStack.authSys.config.security.PermissionsConfig;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import jakarta.annotation.PostConstruct;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthorizationService {
    private final ConcurrentHashMap<Roles, Set<Permissions>> rolePermissions = new ConcurrentHashMap<>();
    private final PermissionsConfig permissionsConfig;

    public AuthorizationService(PermissionsConfig permissionsConfig) {
        this.permissionsConfig = permissionsConfig;
        reloadPermissions();
    }

    @Scheduled(fixedDelay = 30000) // Reload every 30 seconds
    @PostConstruct
    public void reloadPermissions() {
        permissionsConfig.getRoles().forEach((role, perms) ->
                rolePermissions.put(role, ConcurrentHashMap.newKeySet(perms.size()))
        );
    }
}
