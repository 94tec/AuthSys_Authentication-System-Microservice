package com.techStack.authSys.config;

import com.techStack.authSys.models.Permissions;
import com.techStack.authSys.models.Roles;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.*;
import java.util.stream.Collectors;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "permissions")
public class PermissionsConfig {

    // Maps base role to permissions
    private Map<Roles, Set<Permissions>> roles = new HashMap<>();

    // Maps role overrides (special case additions)
    private Map<Roles, Set<Permissions>> roleOverrides = new HashMap<>();

    // Attribute-based access rules
    private Map<String, List<AttributeRule>> attributeRules = new HashMap<>();

    // Rule model for ABAC
    @Getter
    @Setter
    public static class AttributeRule {
        private List<String> roles;  // Change from Roles[] to List<String>
        private Integer minLevel;    // Use Integer instead of int for optional fields
        private boolean required;
    }

    // Combine base + overrides
    public Set<Permissions> getPermissionsForRole(Roles role) {
        Set<Permissions> basePermissions = new HashSet<>(roles.getOrDefault(role, Collections.emptySet()));
        Set<Permissions> overrides = roleOverrides.getOrDefault(role, Collections.emptySet());
        basePermissions.addAll(overrides);
        return basePermissions;
    }

    // Setter for YAML loading of `roles:`
    public void setRoles(Map<String, List<String>> rawRoles) {
        roles = new HashMap<>();
        rawRoles.forEach((roleName, perms) -> {
            Roles.fromName(roleName).ifPresent(role -> {
                Set<Permissions> permsSet = perms.stream()
                        .map(String::toUpperCase)
                        .map(Permissions::valueOf)
                        .collect(Collectors.toSet());
                roles.put(role, permsSet);
            });
        });
    }

    // Setter for YAML loading of `role-overrides:`
    public void setRoleOverrides(Map<String, List<String>> rawOverrides) {
        roleOverrides = new HashMap<>();
        rawOverrides.forEach((roleName, perms) -> {
            Roles.fromName(roleName).ifPresent(role -> {
                Set<Permissions> permsSet = perms.stream()
                        .map(String::toUpperCase)
                        .map(Permissions::valueOf)
                        .collect(Collectors.toSet());
                roleOverrides.put(role, permsSet);
            });
        });
    }

}
