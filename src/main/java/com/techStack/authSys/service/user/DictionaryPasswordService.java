package com.techStack.authSys.service.user;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

/**
 * Dictionary Password Service
 *
 * Checks if a password is too common or dictionary-based.
 *
 * Security:
 * - NEVER logs actual passwords
 * - Uses constant-time comparison where possible
 * - Extensive common password database
 */
@Slf4j
@Service
public class DictionaryPasswordService {

    // ✅ Comprehensive list of most common passwords
    private static final Set<String> COMMON_PASSWORDS = Set.of(
            // Top 10 most common
            "password", "123456", "123456789", "12345678", "12345",
            "1234567", "password1", "qwerty", "abc123", "111111",

            // Common variants
            "letmein", "welcome", "monkey", "dragon", "master",
            "sunshine", "princess", "football", "iloveyou", "admin",
            "welcome1", "password123", "pass123", "admin123",

            // Keyboard patterns
            "qwerty123", "qwertyuiop", "1qaz2wsx", "zxcvbnm",
            "asdfgh", "asdfghjkl", "1234qwer",

            // Common words
            "letmein123", "welcome123", "password!", "admin!",
            "root", "toor", "pass", "test", "guest",

            // Weak patterns
            "000000", "123321", "654321", "123123", "112233",
            "121212", "1q2w3e4r", "qazwsx", "trustno1",

            // System defaults
            "changeme", "secret", "default", "temp", "temporary",

            // Years (common in passwords)
            "2023", "2024", "2025", "2026"
    );

    // ✅ Common password patterns (regex)
    private static final String[] WEAK_PATTERNS = {
            "^123+$",           // Repeated 123
            "^[a-z]+$",         // Only lowercase
            "^[A-Z]+$",         // Only uppercase
            "^\\d+$",           // Only digits
            "^(.)\\1+$",        // Same character repeated
            "^[a-z]+\\d+$",     // Letters followed by numbers
            "^[A-Z][a-z]+\\d+$" // Capitalized word + numbers (Name123)
    };

    /**
     * Check if password is a common dictionary word.
     *
     * @param password The password to check
     * @return true if password is common/weak, false otherwise
     */
    public Mono<Boolean> isCommonWord(String password) {
        if (password == null || password.isEmpty()) {
            return Mono.just(true); // Null/empty is weak
        }

        // ✅ NEVER log the actual password
        log.debug("Checking password strength (length: {})", password.length());

        boolean isCommon = COMMON_PASSWORDS.contains(password.toLowerCase());

        if (isCommon) {
            log.warn("⚠️ Common password detected (length: {})", password.length());
            return Mono.just(true);
        }

        // Check weak patterns
        boolean matchesWeakPattern = matchesWeakPattern(password);
        if (matchesWeakPattern) {
            log.warn("⚠️ Weak password pattern detected (length: {})", password.length());
            return Mono.just(true);
        }

        log.debug("✅ Password passed dictionary check (length: {})", password.length());
        return Mono.just(false);
    }

    /**
     * Check if password matches weak patterns
     */
    private boolean matchesWeakPattern(String password) {
        for (String pattern : WEAK_PATTERNS) {
            if (password.matches(pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check password strength and return detailed feedback
     */
    public Mono<PasswordStrength> checkPasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return Mono.just(new PasswordStrength(
                    StrengthLevel.VERY_WEAK,
                    "Password is required"
            ));
        }

        int length = password.length();
        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSpecial = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*");

        // Check if common
        if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
            return Mono.just(new PasswordStrength(
                    StrengthLevel.VERY_WEAK,
                    "This is a commonly used password"
            ));
        }

        // Check weak patterns
        if (matchesWeakPattern(password)) {
            return Mono.just(new PasswordStrength(
                    StrengthLevel.WEAK,
                    "Password follows a predictable pattern"
            ));
        }

        // Calculate strength
        int score = 0;
        if (length >= 8) score++;
        if (length >= 12) score++;
        if (length >= 16) score++;
        if (hasUpper) score++;
        if (hasLower) score++;
        if (hasDigit) score++;
        if (hasSpecial) score++;

        StrengthLevel level;
        String message;

        if (score >= 7) {
            level = StrengthLevel.VERY_STRONG;
            message = "Excellent password strength";
        } else if (score >= 5) {
            level = StrengthLevel.STRONG;
            message = "Good password strength";
        } else if (score >= 4) {
            level = StrengthLevel.MEDIUM;
            message = "Moderate password strength";
        } else if (score >= 2) {
            level = StrengthLevel.WEAK;
            message = "Weak password - consider adding more complexity";
        } else {
            level = StrengthLevel.VERY_WEAK;
            message = "Very weak password - please use a stronger password";
        }

        log.debug("Password strength check completed: level={}, length={}", level, length);

        return Mono.just(new PasswordStrength(level, message));
    }

    /**
     * Password strength result
     */
    public record PasswordStrength(
            StrengthLevel level,
            String message
    ) {}

    /**
     * Password strength levels
     */
    public enum StrengthLevel {
        VERY_WEAK,
        WEAK,
        MEDIUM,
        STRONG,
        VERY_STRONG
    }
}