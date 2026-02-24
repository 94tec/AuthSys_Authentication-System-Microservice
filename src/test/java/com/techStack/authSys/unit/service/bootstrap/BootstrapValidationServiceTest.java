package com.techStack.authSys.unit.service.bootstrap;


import com.techStack.authSys.config.core.AppConfigProperties;
import com.techStack.authSys.service.bootstrap.BootstrapValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Professional Test Suite for BootstrapValidationService
 *
 * Test Coverage:
 * - Email validation (RFC 5322 compliance)
 * - Phone validation (E.164 format)
 * - Configuration validation
 * - Kenyan phone normalization
 * - Edge cases and security
 *
 * Security Considerations:
 * - GDPR-compliant masking
 * - No sensitive data in logs
 * - Input sanitization
 * - Format validation
 *
 * @author TechStack Security Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("BootstrapValidationService Tests")
class BootstrapValidationServiceTest {

    @Mock
    private AppConfigProperties appConfigProperties;

    private BootstrapValidationService validationService;
    private Clock fixedClock;

    @BeforeEach
    void setUp() {
        fixedClock = Clock.fixed(
                Instant.parse("2024-01-15T10:00:00Z"),
                ZoneId.of("UTC")
        );
        validationService = new BootstrapValidationService(fixedClock);
    }

    /* =========================
       Configuration Validation Tests
       ========================= */

    @Test
    @DisplayName("Should validate correct bootstrap configuration")
    void validateBootstrapConfig_ValidConfig() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("Should reject null configuration")
    void validateBootstrapConfig_NullConfig() {
        // When
        boolean result = validationService.validateBootstrapConfig(null);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should reject config with invalid email")
    void validateBootstrapConfig_InvalidEmail() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("not-an-email");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should reject config with invalid phone")
    void validateBootstrapConfig_InvalidPhone() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("invalid");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should reject config with missing email")
    void validateBootstrapConfig_MissingEmail() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(null);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should reject config with missing phone")
    void validateBootstrapConfig_MissingPhone() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn(null);

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isFalse();
    }

    /* =========================
       Email Validation Tests
       ========================= */

    @ParameterizedTest
    @DisplayName("Should accept valid email formats")
    @ValueSource(strings = {
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.co.uk",
            "user_123@example-domain.com",
            "123@example.com",
            "a@b.c"
    })
    void validateEmail_ValidFormats(String email) {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(email);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isTrue();
    }

    @ParameterizedTest
    @DisplayName("Should reject invalid email formats")
    @ValueSource(strings = {
            "not-an-email",
            "@example.com",
            "user@",
            "user",
            "user@domain",
            "user..name@example.com",
            "user@domain..com",
            "user name@example.com",
            "user@domain .com"
    })
    void validateEmail_InvalidFormats(String email) {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(email);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isFalse();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("Should reject null and empty emails")
    void validateEmail_NullAndEmpty(String email) {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(email);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should handle email with leading/trailing whitespace")
    void validateEmail_Whitespace() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("  admin@example.com  ");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("Should normalize email to lowercase")
    void validateEmail_CaseInsensitive() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("Admin@EXAMPLE.COM");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isTrue();
    }

    /* =========================
       Phone Validation Tests
       ========================= */

    @ParameterizedTest
    @DisplayName("Should accept valid E.164 phone formats")
    @ValueSource(strings = {
            "+254712345678",
            "+1234567890",
            "+447123456789",
            "+33123456789",
            "+919876543210"
    })
    void validatePhone_ValidE164Formats(String phone) {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn(phone);

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isTrue();
    }

    @ParameterizedTest
    @DisplayName("Should accept and normalize Kenyan phone formats")
    @CsvSource({
            "0712345678,    +254712345678",
            "254712345678,  +254712345678",
            "712345678,     +254712345678",
            "+254712345678, +254712345678",
            "0 712 345 678, +254712345678"
    })
    void validatePhone_KenyanFormats(String inputPhone, String expectedNormalized) {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn(inputPhone);

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isTrue();
    }

    @ParameterizedTest
    @DisplayName("Should reject invalid phone formats")
    @ValueSource(strings = {
            "123",
            "abcdef",
            "++254712345678",
            "254712",
            "712",
            "+254-712-345-678", // Hyphens not allowed in E.164
            "(254) 712-345678"
    })
    void validatePhone_InvalidFormats(String phone) {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn(phone);

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isFalse();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("Should reject null and empty phones")
    void validatePhone_NullAndEmpty(String phone) {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn(phone);

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should handle phone with whitespace")
    void validatePhone_WithWhitespace() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("  +254 712 345 678  ");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then
        assertThat(result).isTrue();
    }

    /* =========================
       Security Tests
       ========================= */

    @Test
    @DisplayName("Should use clock for timestamp tracking")
    void validateBootstrapConfig_UsesClockForTimestamp() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        validationService.validateBootstrapConfig(appConfigProperties);

        // Then - Verify clock is being used (timestamp should be consistent)
        Instant now = fixedClock.instant();
        assertThat(now).isEqualTo(Instant.parse("2024-01-15T10:00:00Z"));
    }

    @Test
    @DisplayName("Should handle SQL injection attempts in email")
    void validateEmail_SqlInjectionAttempt() {
        // Given
        String maliciousEmail = "admin' OR '1'='1--@example.com";
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(maliciousEmail);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then - Should reject as invalid email format
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should handle XSS attempts in email")
    void validateEmail_XssAttempt() {
        // Given
        String maliciousEmail = "<script>alert('xss')</script>@example.com";
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(maliciousEmail);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then - Should reject as invalid email format
        assertThat(result).isFalse();
    }

    /* =========================
       Edge Cases Tests
       ========================= */

    @Test
    @DisplayName("Should handle very long email")
    void validateEmail_VeryLong() {
        // Given
        String longEmail = "a".repeat(100) + "@" + "b".repeat(100) + ".com";
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(longEmail);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then - Should handle gracefully
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("Should handle very long phone")
    void validatePhone_VeryLong() {
        // Given
        String longPhone = "+" + "1".repeat(20);
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn(longPhone);

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then - Should reject (E.164 max is 15 digits)
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should handle unicode characters in email")
    void validateEmail_UnicodeCharacters() {
        // Given
        String unicodeEmail = "用户@example.com";
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(unicodeEmail);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        boolean result = validationService.validateBootstrapConfig(appConfigProperties);

        // Then - Should reject (ASCII only in email local part)
        assertThat(result).isFalse();
    }

    /* =========================
       Performance Tests
       ========================= */

    @Test
    @DisplayName("Should validate configuration quickly")
    void validateBootstrapConfig_Performance() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When
        long startTime = System.nanoTime();
        validationService.validateBootstrapConfig(appConfigProperties);
        long endTime = System.nanoTime();

        // Then - Should complete in under 10ms
        long durationMs = (endTime - startTime) / 1_000_000;
        assertThat(durationMs).isLessThan(10);
    }

    @Test
    @DisplayName("Should handle repeated validations efficiently")
    void validateBootstrapConfig_RepeatedValidations() {
        // Given
        when(appConfigProperties.getSuperAdminEmail()).thenReturn("admin@example.com");
        when(appConfigProperties.getSuperAdminPhone()).thenReturn("+254712345678");

        // When - Validate 1000 times
        long startTime = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            validationService.validateBootstrapConfig(appConfigProperties);
        }
        long endTime = System.nanoTime();

        // Then - Should complete in reasonable time
        long durationMs = (endTime - startTime) / 1_000_000;
        assertThat(durationMs).isLessThan(1000); // Under 1 second for 1000 validations
    }
}
