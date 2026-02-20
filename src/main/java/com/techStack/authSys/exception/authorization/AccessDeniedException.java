package com.techStack.authSys.exception.authorization;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Access Denied Exception
 *
 * Maps to HTTP 403 FORBIDDEN.
 */
public class AccessDeniedException extends CustomException {

    private static final String DEFAULT_CODE = "ACCESS_DENIED";

    public AccessDeniedException(String message) {
        super(HttpStatus.FORBIDDEN, message, null, DEFAULT_CODE);
    }

    public AccessDeniedException(String message, String errorCode) {
        super(HttpStatus.FORBIDDEN, message, null, errorCode);
    }

    public AccessDeniedException(String message, Throwable cause) {
        super(HttpStatus.FORBIDDEN, message, cause, null, DEFAULT_CODE);
    }

    public AccessDeniedException(String message, Throwable cause, String errorCode) {
        super(HttpStatus.FORBIDDEN, message, cause, null, errorCode);
    }

    /* =========================
       Factory Methods
       ========================= */

    public static AccessDeniedException insufficientRole(String requiredRole, String actualRole) {
        return new AccessDeniedException(
                String.format("Insufficient permissions. Required: %s, Actual: %s",
                        requiredRole, actualRole),
                "INSUFFICIENT_ROLE"
        );
    }

    public static AccessDeniedException cannotManageHigherPrivilege(String performerRole, String targetRole) {
        return new AccessDeniedException(
                String.format("Role %s cannot manage user with role %s",
                        performerRole, targetRole),
                "CANNOT_MANAGE_HIGHER_PRIVILEGE"
        );
    }

    public static AccessDeniedException operationNotAllowed(String operation, String role) {
        return new AccessDeniedException(
                String.format("Operation '%s' not allowed for role %s",
                        operation, role),
                "OPERATION_NOT_ALLOWED"
        );
    }
}
