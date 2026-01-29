package com.techStack.authSys.exception.password;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

import java.util.List;

/**
 * Weak password exception with requirements
 */
public class WeakPasswordException extends CustomException {
    private final List<String> passwordRequirements;
    private final List<String> violations;

    public WeakPasswordException(String message,
                                 List<String> requirements,
                                 List<String> violations) {
        super(HttpStatus.BAD_REQUEST, message);
        this.passwordRequirements = requirements;
        this.violations = violations;
    }

    public List<String> getPasswordRequirements() {
        return passwordRequirements;
    }

    public List<String> getViolations() {
        return violations;
    }
}
