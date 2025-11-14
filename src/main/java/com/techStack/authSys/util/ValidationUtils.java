package com.techStack.authSys.util;

import com.techStack.authSys.dto.SecurityContext;
import com.techStack.authSys.models.User;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Clean, powerful, and secure validation utility class
 * Provides comprehensive validation methods with meaningful error messages
 */
@Component
public class ValidationUtils {

    private ValidationUtils() {
        // Utility class - prevent instantiation
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Validates that an object is not null
     */
    public static <T> T validateNotNull(T object, String message) {
        if (object == null) {
            throw new IllegalArgumentException(message);
        }
        return object;
    }

    /**
     * Validates that an object is not null with parameterized message
     */
    public static <T> T validateNotNull(T object, String message, Object... args) {
        if (object == null) {
            throw new IllegalArgumentException(String.format(message, args));
        }
        return object;
    }

    /**
     * Validates that a string is not blank (not null, not empty, not whitespace only)
     */
    public static String validateNotBlank(String value, String message) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(message);
        }
        return value.trim();
    }

    /**
     * Validates that a collection is not null and not empty
     */
    public static <T extends Collection<?>> T validateNotEmpty(T collection, String message) {
        validateNotNull(collection, message);
        if (collection.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
        return collection;
    }

    /**
     * Validates that an array is not null and not empty
     */
    public static <T> T[] validateNotEmpty(T[] array, String message) {
        validateNotNull(array, message);
        if (array.length == 0) {
            throw new IllegalArgumentException(message);
        }
        return array;
    }

    /**
     * Validates that a string matches email format
     */
    public static String validateEmail(String email, String message) {
        String cleanEmail = validateNotBlank(email, message);

        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        if (!cleanEmail.matches(emailRegex)) {
            throw new IllegalArgumentException(message);
        }
        return cleanEmail;
    }

    /**
     * Validates that a number is positive
     */
    public static <T extends Number> T validatePositive(T number, String message) {
        validateNotNull(number, message);

        if (number.doubleValue() <= 0) {
            throw new IllegalArgumentException(message);
        }
        return number;
    }

    /**
     * Validates that a number is within range (inclusive)
     */
    public static <T extends Number & Comparable<T>> T validateInRange(T value, T min, T max, String message) {
        validateNotNull(value, "Value cannot be null");
        validateNotNull(min, "Min value cannot be null");
        validateNotNull(max, "Max value cannot be null");

        if (value.compareTo(min) < 0 || value.compareTo(max) > 0) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }

    /**
     * Validates that a condition is true
     */
    public static void validateCondition(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Validates that a string has minimum length
     */
    public static String validateMinLength(String value, int minLength, String message) {
        String cleanValue = validateNotBlank(value, message);

        if (cleanValue.length() < minLength) {
            throw new IllegalArgumentException(message);
        }
        return cleanValue;
    }

    /**
     * Validates that a string has maximum length
     */
    public static String validateMaxLength(String value, int maxLength, String message) {
        validateNotNull(value, message);

        if (value.length() > maxLength) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }

    /**
     * Validates that a string matches a regex pattern
     */
    public static String validatePattern(String value, String regex, String message) {
        String cleanValue = validateNotBlank(value, message);

        if (!cleanValue.matches(regex)) {
            throw new IllegalArgumentException(message);
        }
        return cleanValue;
    }


    /**
     * Validates authentication object with detailed security context
     */
    public static Authentication validateAuthentication(Authentication authentication) {
        if (authentication == null) {
            throw new SecurityException("Authentication cannot be null - security context required");
        }

        if (!authentication.isAuthenticated()) {
            throw new SecurityException("Authentication must be authenticated - invalid security context");
        }

        if (authentication.getName() == null || authentication.getName().trim().isEmpty()) {
            throw new SecurityException("Authentication must have a valid principal name");
        }

        return authentication;
    }

    /**
     * Validates security context with comprehensive checks
     */
    public static SecurityContext validateSecurityContext(SecurityContext context) {
        if (context == null) {
            throw new SecurityException("Security context cannot be null");
        }

        validateNotBlank(context.getRequesterEmail(), "Security context must have requester email");
        validateNotNull(context.getRequesterRole(), "Security context must have requester role");
        validateNotNull(context.getAuthenticationTime(), "Security context must have authentication time");

        return context;
    }

    /**
     * Validates user object for approval workflows
     */
    public static User validateUserForApproval(User user) {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null for approval processing");
        }

        validateNotBlank(user.getId(), "User must have an ID");
        validateNotBlank(user.getEmail(), "User must have an email");
        validateNotBlank(user.getFirstName(), "User must have a first name");
        validateNotBlank(user.getLastName(), "User must have a last name");
        validateNotEmpty(user.getRoles(), "User must have at least one role");
        validateNotNull(user.getStatus(), "User must have a status");

        return user;
    }

    /**
     * Batch validation - validates multiple validations at once
     */
    public static void validateAll(Validation... validations) {
        if (validations == null || validations.length == 0) {
            return;
        }

        List<String> errors = new ArrayList<>();
        for (Validation validation : validations) {
            try {
                validation.validate();
            } catch (Exception e) {
                errors.add(e.getMessage());
            }
        }

        if (!errors.isEmpty()) {
            throw new IllegalArgumentException("Multiple validation errors: " + String.join("; ", errors));
        }
    }

    /**
     * Functional interface for custom validations
     */
    @FunctionalInterface
    public interface Validation {
        void validate();
    }

    /**
     * Validation result for complex validation scenarios
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String message;

        private ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        public static ValidationResult valid() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult invalid(String message) {
            return new ValidationResult(false, message);
        }

        public boolean isValid() {
            return valid;
        }

        public String getMessage() {
            return message;
        }

        public void throwIfInvalid() {
            if (!valid) {
                throw new IllegalArgumentException(message);
            }
        }
    }
}
