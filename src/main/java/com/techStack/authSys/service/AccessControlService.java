package com.techStack.authSys.service;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.security.GranularAccessControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;

@Service
public class AccessControlService {
    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);

    private final GranularAccessControl accessControl;
    private final FirebaseAuth firebaseAuth;

    public AccessControlService(GranularAccessControl accessControl, FirebaseAuth firebaseAuth) {
        this.accessControl = accessControl;
        this.firebaseAuth = firebaseAuth;
    }

    /**
     * Assigns default permissions to a user in Firebase Custom Claims.
     * Firebase does not store permissions in a DB, so we assign them per user.
     */
    public void assignDefaultPermissions(String uid) {
        Set<String> defaultPermissions = Set.of(
                "user:create:global",
                "inventory:update:department",
                "order:view:region"
        );

        try {
            accessControl.assignPermissions(uid, defaultPermissions);
            log.info("Default permissions assigned to user {}", uid);
        } catch (Exception e) {
            log.error("Failed to assign default permissions for user {}: {}", uid, e.getMessage());
        }
    }

    /**
     * Enforces permission-based access control.
     * @param idToken The Firebase ID token from the user
     * @param resource The resource being accessed
     * @param action The action the user wants to perform
     */
    public void enforceAccess(String idToken, String resource, String action) {
        try {
            FirebaseToken token = firebaseAuth.verifyIdToken(idToken);
            String uid = token.getUid();

            if (!accessControl.checkAccess(idToken, resource, action)) {
                throw new AccessDeniedException(
                        String.format("User %s lacks %s permission for %s", uid, action, resource)
                );
            }
        } catch (FirebaseAuthException e) {
            throw new AccessDeniedException("Invalid Firebase token.");
        }
    }
}
