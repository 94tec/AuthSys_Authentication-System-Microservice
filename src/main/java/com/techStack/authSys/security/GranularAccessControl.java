package com.techStack.authSys.security;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.config.PermissionsConfig;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.models.Roles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class GranularAccessControl {
    private static final Logger logger = LoggerFactory.getLogger(GranularAccessControl.class);

    private final FirebaseAuth firebaseAuth;
    private final PermissionsConfig permissionsConfig;

    public GranularAccessControl(FirebaseAuth firebaseAuth, PermissionsConfig permissionsConfig) {
        this.firebaseAuth = firebaseAuth;
        this.permissionsConfig = permissionsConfig;
    }
    public Set<String> getDefaultPermissionsForRoles(Set<String> roles) {
        Set<String> permissions = new HashSet<>();

        for (String role : roles) {
            try {
                Roles roleEnum = Roles.valueOf(role.toUpperCase());

                // Convert Permission enums to Strings before adding
                permissions.addAll(
                        permissionsConfig.getPermissionsForRole(roleEnum)
                                .stream()
                                .map(Enum::name)  // Convert Permission enum to String
                                .collect(Collectors.toSet())
                );

            } catch (IllegalArgumentException e) {
                logger.warn("Unknown role: {}", role);
            }
        }


        return permissions;
    }

    public boolean checkPermission(String idToken, String resource, String action) {
        try {
            FirebaseToken token = firebaseAuth.verifyIdToken(idToken);
            Map<String, Object> claims = token.getClaims();

            // Check RBAC permissions
            if (claims.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) claims.get("roles");
                if (hasRolePermission(roles, resource, action)) {
                    return true;
                }
            }

            // Check granular permissions
            if (claims.containsKey("permissions")) {
                @SuppressWarnings("unchecked")
                Set<String> permissions = (Set<String>) claims.get("permissions");
                return permissions.contains(formatPermission(resource, action));
            }

            return false;
        } catch (FirebaseAuthException e) {
            logger.error("Failed to verify token: {}", e.getMessage());
            return false;
        }
    }

    private boolean hasRolePermission(List<String> roles, String resource, String action) {
        for (String role : roles) {
            try {
                Roles roleEnum = Roles.valueOf(role.toUpperCase());

                // Convert Permission enum values to String
                Set<String> permissions = permissionsConfig.getPermissionsForRole(roleEnum)
                        .stream()
                        .map(Enum::name)  // Convert Enum to String
                        .collect(Collectors.toSet());

                // Check if the resource is in the permissions set
                if (permissions.contains(resource)) {
                    return true;
                }

            } catch (IllegalArgumentException e) {
                logger.warn("Unknown role: {}", role);
            }
        }

        return false;
    }

    private String formatPermission(String resource, String action) {
        return String.format("%s:%s", resource.toLowerCase(), action.toLowerCase());
    }
    /**
     * Checks if a user has permission to access a resource with a specific action.
     * @param idToken The Firebase ID token from the user
     * @param resource The resource being accessed
     * @param action The action the user wants to perform
     * @return true if the user has permission, false otherwise
     */
    public boolean checkAccess(String idToken, String resource, String action) {
        try {
            // Verify Firebase token and extract claims
            FirebaseToken token = firebaseAuth.verifyIdToken(idToken);
            Map<String, Object> claims = token.getClaims();

            if (!claims.containsKey("permissions")) return false;

            Set<String> permissions = (Set<String>) claims.get("permissions");

            return permissions.contains(formatResourceActionPermission(resource, action));

        } catch (FirebaseAuthException e) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid Firebase token.");
        }
    }

    /**
     * Formats a permission string in "resource:action" format.
     */
    private String formatResourceActionPermission(String resource, String action) {
        return String.format("%s:%s", resource.toLowerCase(), action.toLowerCase());
    }

    /**
     * Assigns granular permissions to a user in Firebase.
     * @param uid The Firebase user ID
     * @param permissions The set of permissions to assign
     */
    public void assignPermissions(String uid, Set<String> permissions) {
        try {
            firebaseAuth.setCustomUserClaims(uid, Map.of("permissions", permissions));
        } catch (FirebaseAuthException e) {
            throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to assign permissions.");
        }
    }
}
