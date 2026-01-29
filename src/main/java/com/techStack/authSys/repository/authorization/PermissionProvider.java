package com.techStack.authSys.repository.authorization;

import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;

@Service
public interface PermissionProvider {
    Set<Permissions> getPermissionsForRole(Roles role);
    void reloadPermissions();

    Mono<Void> assignRole(String userId, Roles role);

    void addUserAttribute(String userId, String namespace, String key, String value);

    // --- User-specific permission management ---
    void addPermission(String userId, Permissions permission);

    void removePermission(String userId, Permissions permission);

    // Additional interface methods (example implementation)
    String[] getPermissions();

    String[] getSubPermissions(String perm);

    Object getLoadedRoles();

    Set<String> resolveEffectivePermission(User user);

    List<Permissions> deserializePermissions(List<String> permissions);

    Set<String> resolveEffectivePermissions(User user);

    // New PermissionValidator.java
    @Component
    public class PermissionValidator {

        // Validate if granted permission has enough privileges for required permission
        public boolean validatePermissionChain(Permissions granted, Permissions required) {
            if (granted == Permissions.ADMIN) {
                return true;  // ADMIN has access to everything
            }
            if (granted == Permissions.MANAGER) {
                return required.level <= Permissions.MANAGER.level; // Use 'level' directly
            }
            // For any other roles, check if granted permission has higher or equal privileges
            return granted.hasAtLeastPrivilegesOf(required);
        }
    }
}
