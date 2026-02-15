package com.techStack.authSys.unit.config;

import com.techStack.authSys.config.core.LoginOtpProperties;
import com.techStack.authSys.repository.security.RateLimiterService;
import com.techStack.authSys.service.auth.*;
import com.techStack.authSys.service.bootstrap.AdminUserManagementService;
import com.techStack.authSys.service.bootstrap.TransactionalBootstrapService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.service.token.TokenGenerationService;
import com.techStack.authSys.service.validation.CredentialValidationService;
import com.techStack.authSys.service.verification.EmailVerificationService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

/**
 * Test Configuration for Authentication Tests
 *
 * Provides test-specific beans and utilities:
 * - Fixed clock for deterministic testing
 * - Mocked external dependencies (Firebase, Redis, Email)
 * - Test-specific configurations
 * - Simplified metrics for testing
 */
@TestConfiguration
@Profile("test")
public class AuthTestConfiguration {

    /* =========================
       Clock Configuration
       ========================= */

    /**
     * Fixed clock for deterministic testing.
     * All tests will use this timestamp: 2026-02-14T10:00:00Z
     */
    @Bean
    @Primary
    public Clock testClock() {
        return Clock.fixed(
                Instant.parse("2026-02-14T10:00:00Z"),
                ZoneId.systemDefault()
        );
    }

    /**
     * Alternative: System clock for tests that need real time
     */
    @Bean
    public Clock systemClock() {
        return Clock.systemDefaultZone();
    }

    /* =========================
       Mocked Service Dependencies
       ========================= */

    /**
     * Mock Firebase service for testing without Firebase dependency
     */
    @Bean
    @Primary
    public FirebaseServiceAuth mockFirebaseServiceAuth() {
        return Mockito.mock(FirebaseServiceAuth.class);
    }

    /**
     * Mock JWT service for token operations in tests
     */
    @Bean
    @Primary
    public JwtService mockJwtService() {
        return Mockito.mock(JwtService.class);
    }

    /**
     * Mock device verification service
     */
    @Bean
    @Primary
    public DeviceVerificationService mockDeviceVerificationService() {
        return Mockito.mock(DeviceVerificationService.class);
    }

    /**
     * Mock rate limiter service (disabled by default in tests)
     */
    @Bean
    @Primary
    public RateLimiterService mockRateLimiterService() {
        RateLimiterService mock = Mockito.mock(RateLimiterService.class);
        // By default, rate limiting always passes in tests
        Mockito.when(mock.checkAuthRateLimit(Mockito.anyString(), Mockito.anyString()))
                .thenReturn(reactor.core.publisher.Mono.empty());
        return mock;
    }

    /**
     * Mock login OTP service
     */
    @Bean
    @Primary
    public LoginOtpService mockLoginOtpService() {
        return Mockito.mock(LoginOtpService.class);
    }

    /**
     * Mock email verification service
     */
    @Bean
    @Primary
    public EmailVerificationService mockEmailVerificationService() {
        return Mockito.mock(EmailVerificationService.class);
    }

    /**
     * Mock credential validation service
     */
    @Bean
    @Primary
    public CredentialValidationService mockCredentialValidationService() {
        return Mockito.mock(CredentialValidationService.class);
    }

    /**
     * Mock token generation service
     */
    @Bean
    @Primary
    public TokenGenerationService mockTokenGenerationService() {
        return Mockito.mock(TokenGenerationService.class);
    }

    @Bean
    @Primary
    public AuthenticationEventService mockAuthenticationEventService() {
        AuthenticationEventService mock = Mockito.mock(AuthenticationEventService.class);

        Mockito.doNothing().when(mock).handleSuccessfulAuthentication(
                Mockito.any(),
                Mockito.anyString(),
                Mockito.any(),
                Mockito.anyString(),
                Mockito.anyString()
        );

        Mockito.doNothing().when(mock).handleFailedAuthentication(
                Mockito.anyString(),
                Mockito.any(),
                Mockito.any(),
                Mockito.anyString(),
                Mockito.anyString(),
                Mockito.anyString(),
                Mockito.any()
        );

        return mock;
    }


    /**
     * Mock logout service
     */
    @Bean
    @Primary
    public LogoutService mockLogoutService() {
        LogoutService mock = Mockito.mock(LogoutService.class);
        Mockito.when(mock.logout(Mockito.anyString(), Mockito.anyString()))
                .thenReturn(reactor.core.publisher.Mono.empty());
        return mock;
    }

    /**
     * Mock login response builder
     */
    @Bean
    @Primary
    public LoginResponseBuilder mockLoginResponseBuilder() {
        return Mockito.mock(LoginResponseBuilder.class);
    }

    /**
     * Mock authentication orchestrator
     */
    @Bean
    @Primary
    public AuthenticationOrchestrator mockAuthenticationOrchestrator() {
        return Mockito.mock(AuthenticationOrchestrator.class);
    }

    /**
     * Mock auth service
     */
    @Bean
    @Primary
    public AuthService mockAuthService() {
        return Mockito.mock(AuthService.class);
    }

    /* =========================
       Bootstrap Service Mocks
       ========================= */

    /**
     * Mock transactional bootstrap service
     */
    @Bean
    @Primary
    public TransactionalBootstrapService mockTransactionalBootstrapService() {
        return Mockito.mock(TransactionalBootstrapService.class);
    }

    /**
     * Mock admin user management service
     */
    @Bean
    @Primary
    public AdminUserManagementService mockAdminUserManagementService() {
        return Mockito.mock(AdminUserManagementService.class);
    }

    /* =========================
       Metrics Configuration
       ========================= */

    /**
     * Simple meter registry for testing (doesn't persist metrics)
     */
    @Bean
    @Primary
    public MeterRegistry testMeterRegistry() {
        return new SimpleMeterRegistry();
    }

    /* =========================
       Test Properties
       ========================= */

    /**
     * Test-specific Login OTP properties
     * Mock for test configuration - actual properties loaded from application-test.yml
     */
    @Bean
    @Primary
    public LoginOtpProperties testLoginOtpProperties() {
        // Return a mock that returns sensible defaults for tests
        LoginOtpProperties mock = Mockito.mock(LoginOtpProperties.class);
        Mockito.when(mock.isEnabled()).thenReturn(true);
        return mock;
    }

    /* =========================
       Test Utilities
       ========================= */

    /**
     * Test data factory helper
     */
    @Bean
    public TestDataFactory testDataFactory() {
        return new TestDataFactory();
    }

    /**
     * Helper class for creating test data
     */
    public static class TestDataFactory {

        public String generateTestEmail() {
            return "test-" + System.currentTimeMillis() + "@example.com";
        }

        public String generateTestPassword() {
            return "TestPass123!";
        }

        public String generateTestPhone() {
            return "+1234567890";
        }

        public String generateDeviceFingerprint() {
            return "device-" + System.currentTimeMillis();
        }

        public String generateIpAddress() {
            return "192.168.1." + (int)(Math.random() * 255);
        }

        public String generateUserAgent() {
            return "Mozilla/5.0 (Test Agent)";
        }

        public String generateUserId() {
            return "user-" + System.currentTimeMillis();
        }

        public String generateAccessToken() {
            return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                    "eyJzdWIiOiJ0ZXN0In0." +
                    java.util.UUID.randomUUID().toString();
        }

        public String generateRefreshToken() {
            return "refresh_" + java.util.UUID.randomUUID().toString();
        }

        public String generateTemporaryToken() {
            return "temp_" + java.util.UUID.randomUUID().toString();
        }
    }
}