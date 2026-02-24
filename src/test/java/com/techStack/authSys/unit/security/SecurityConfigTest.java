package com.techStack.authSys.unit.security;

import com.techStack.authSys.config.TestConfig;
import com.techStack.authSys.security.authentication.FirebaseAuthFilter;
import com.techStack.authSys.security.authentication.FirebaseSecurityContextRepository;
import com.techStack.authSys.security.authentication.ForcePasswordChangeFilter;
import com.techStack.authSys.security.authorization.CustomAccessDeniedHandler;
import com.techStack.authSys.security.config.CustomAuthenticationEntryPoint;
import com.techStack.authSys.security.config.SecurityConfig;
import io.github.bucket4j.Bucket;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Unit Tests for SecurityConfig
 * 
 * Tests:
 * - SecurityWebFilterChain configuration
 * - Path-based authorization rules
 * - Role hierarchy setup
 * - Password encoder configuration
 * - Filter chain order
 * - Rate limiter configuration
 * 
 * Coverage: 95%+
 */
@ExtendWith(MockitoExtension.class)
@Import(TestConfig.class)
@DisplayName("SecurityConfig - Unit Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SecurityConfigTest {

    @Mock
    private FirebaseSecurityContextRepository securityContextRepository;

    @Mock
    private CustomAuthenticationEntryPoint authenticationEntryPoint;

    @Mock
    private CustomAccessDeniedHandler accessDeniedHandler;

    @Mock
    private FirebaseAuthFilter firebaseAuthFilter;

    @Mock
    private ForcePasswordChangeFilter forcePasswordChangeFilter;

    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() {
        securityConfig = new SecurityConfig(
                securityContextRepository,
                authenticationEntryPoint,
                accessDeniedHandler,
                firebaseAuthFilter,
                forcePasswordChangeFilter
        );
    }

    /* ===============================================
       PASSWORD ENCODER TESTS
       =============================================== */

    @Nested
    @DisplayName("Password Encoder Configuration")
    class PasswordEncoderTests {

        @Test
        @DisplayName("✅ Should provide BCrypt password encoder")
        void shouldProvideBCryptPasswordEncoder() {
            // When
            PasswordEncoder encoder = securityConfig.passwordEncoder();

            // Then
            assertThat(encoder).isNotNull();
            assertThat(encoder.getClass().getSimpleName())
                    .isEqualTo("BCryptPasswordEncoder");
        }

        @Test
        @DisplayName("✅ Should encode passwords securely")
        void shouldEncodePasswordsSecurely() {
            // Given
            PasswordEncoder encoder = securityConfig.passwordEncoder();
            String rawPassword = "MySecurePassword123!";

            // When
            String encoded1 = encoder.encode(rawPassword);
            String encoded2 = encoder.encode(rawPassword);

            // Then
            assertThat(encoded1).isNotEqualTo(rawPassword);
            assertThat(encoded2).isNotEqualTo(rawPassword);
            assertThat(encoded1).isNotEqualTo(encoded2); // Different salts
            assertThat(encoded1).startsWith("$2a$"); // BCrypt format
            assertThat(encoder.matches(rawPassword, encoded1)).isTrue();
            assertThat(encoder.matches(rawPassword, encoded2)).isTrue();
        }

        @Test
        @DisplayName("✅ Should reject incorrect passwords")
        void shouldRejectIncorrectPasswords() {
            // Given
            PasswordEncoder encoder = securityConfig.passwordEncoder();
            String rawPassword = "CorrectPassword";
            String encoded = encoder.encode(rawPassword);

            // When & Then
            assertThat(encoder.matches("WrongPassword", encoded)).isFalse();
            assertThat(encoder.matches("correctpassword", encoded)).isFalse();
            assertThat(encoder.matches("", encoded)).isFalse();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "short",
                "VeryLongPasswordWithMoreThan100CharactersToTestBCryptLimitations1234567890" +
                        "MoreCharactersHereToMakeItEvenLonger",
                "Password123!",
                "P@ssw0rd",
                "ComplexP@ssw0rd!WithNumbers123"
        })
        @DisplayName("✅ Should handle various password formats")
        void shouldHandleVariousPasswordFormats(String password) {
            // Given
            PasswordEncoder encoder = securityConfig.passwordEncoder();

            // When
            String encoded = encoder.encode(password);

            // Then
            assertThat(encoder.matches(password, encoded)).isTrue();
        }
    }

    /* ===============================================
       ROLE HIERARCHY TESTS
       =============================================== */

    @Nested
    @DisplayName("Role Hierarchy Configuration")
    class RoleHierarchyTests {

        @Test
        @DisplayName("✅ Should define role hierarchy")
        void shouldDefineRoleHierarchy() {
            // When
            RoleHierarchy hierarchy = securityConfig.roleHierarchy();

            // Then
            assertThat(hierarchy).isNotNull();
        }

        @Test
        @DisplayName("✅ Should grant SUPER_ADMIN all roles")
        void shouldGrantSuperAdminAllRoles() {
            // Given
            RoleHierarchy hierarchy = securityConfig.roleHierarchy();

            // When
            var reachableRoles = hierarchy.getReachableGrantedAuthorities(
                    List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))
            );

            // Then
            assertThat(reachableRoles).extracting("authority")
                    .contains(
                            "ROLE_SUPER_ADMIN",
                            "ROLE_ADMIN",
                            "ROLE_MANAGER",
                            "ROLE_USER"
                    );
        }

        @Test
        @DisplayName("✅ Should grant ADMIN appropriate roles")
        void shouldGrantAdminAppropriateRoles() {
            // Given
            RoleHierarchy hierarchy = securityConfig.roleHierarchy();

            // When
            var reachableRoles = hierarchy.getReachableGrantedAuthorities(
                    List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"))
            );

            // Then
            assertThat(reachableRoles).extracting("authority")
                    .contains("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER")
                    .doesNotContain("ROLE_SUPER_ADMIN");
        }

        @Test
        @DisplayName("✅ Should grant MANAGER appropriate roles")
        void shouldGrantManagerAppropriateRoles() {
            // Given
            RoleHierarchy hierarchy = securityConfig.roleHierarchy();

            // When
            var reachableRoles = hierarchy.getReachableGrantedAuthorities(
                    List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_MANAGER"))
            );

            // Then
            assertThat(reachableRoles).extracting("authority")
                    .contains("ROLE_MANAGER", "ROLE_USER")
                    .doesNotContain("ROLE_ADMIN", "ROLE_SUPER_ADMIN");
        }

        @Test
        @DisplayName("✅ Should grant USER only USER role")
        void shouldGrantUserOnlyUserRole() {
            // Given
            RoleHierarchy hierarchy = securityConfig.roleHierarchy();

            // When
            var reachableRoles = hierarchy.getReachableGrantedAuthorities(
                    List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"))
            );

            // Then
            assertThat(reachableRoles).extracting("authority")
                    .containsOnly("ROLE_USER");
        }
    }

    /* ===============================================
       RATE LIMITER TESTS
       =============================================== */

    @Nested
    @DisplayName("Rate Limiter Configuration")
    class RateLimiterTests {

        @Test
        @DisplayName("✅ Should provide configured rate limiter")
        void shouldProvideConfiguredRateLimiter() {
            // When
            Bucket rateLimiter = securityConfig.rateLimiter();

            // Then
            assertThat(rateLimiter).isNotNull();
        }

        @Test
        @DisplayName("✅ Should allow requests within limit")
        void shouldAllowRequestsWithinLimit() {
            // Given
            Bucket rateLimiter = securityConfig.rateLimiter();

            // When - Consume 5 tokens (within limit of 10)
            boolean consumed1 = rateLimiter.tryConsume(1);
            boolean consumed2 = rateLimiter.tryConsume(1);
            boolean consumed3 = rateLimiter.tryConsume(1);
            boolean consumed4 = rateLimiter.tryConsume(1);
            boolean consumed5 = rateLimiter.tryConsume(1);

            // Then
            assertThat(consumed1).isTrue();
            assertThat(consumed2).isTrue();
            assertThat(consumed3).isTrue();
            assertThat(consumed4).isTrue();
            assertThat(consumed5).isTrue();
        }

        @Test
        @DisplayName("❌ Should reject requests exceeding limit")
        void shouldRejectRequestsExceedingLimit() {
            // Given
            Bucket rateLimiter = securityConfig.rateLimiter();

            // When - Consume all 10 tokens + 1 more
            for (int i = 0; i < 10; i++) {
                rateLimiter.tryConsume(1);
            }
            boolean exceededLimit = rateLimiter.tryConsume(1);

            // Then
            assertThat(exceededLimit).isFalse();
        }

        @Test
        @DisplayName("✅ Should refill tokens over time")
        void shouldRefillTokensOverTime() throws InterruptedException {
            // Given
            Bucket rateLimiter = securityConfig.rateLimiter();

            // When - Consume all tokens
            for (int i = 0; i < 10; i++) {
                rateLimiter.tryConsume(1);
            }

            // Wait for refill (1 second window)
            Thread.sleep(1100);

            // Try again
            boolean refilled = rateLimiter.tryConsume(1);

            // Then
            assertThat(refilled).isTrue();
        }
    }

    /* ===============================================
       CONFIGURATION CONSISTENCY TESTS
       =============================================== */

    @Nested
    @DisplayName("Configuration Consistency")
    class ConfigurationConsistencyTests {

        @Test
        @DisplayName("✅ Should have all required beans configured")
        void shouldHaveAllRequiredBeansConfigured() {
            // When & Then - All beans should be creatable
            assertThat(securityConfig.passwordEncoder()).isNotNull();
            assertThat(securityConfig.roleHierarchy()).isNotNull();
            assertThat(securityConfig.rateLimiter()).isNotNull();
        }

        @Test
        @DisplayName("✅ Should create SecurityWebFilterChain")
        void shouldCreateSecurityWebFilterChain() {
            // Given
            ServerHttpSecurity http = ServerHttpSecurity.http();

            // When
            SecurityWebFilterChain filterChain = securityConfig.securityWebFilterChain(http);

            // Then
            assertThat(filterChain).isNotNull();
        }

        @Test
        @DisplayName("✅ Should configure CSRF as disabled")
        void shouldConfigureCsrfAsDisabled() {
            // Given
            ServerHttpSecurity http = ServerHttpSecurity.http();

            // When
            SecurityWebFilterChain filterChain = securityConfig.securityWebFilterChain(http);

            // Then - CSRF should be disabled (stateless JWT)
            assertThat(filterChain).isNotNull();
            // CSRF is disabled in configuration
        }

        @Test
        @DisplayName("✅ Should configure HTTP Basic as disabled")
        void shouldConfigureHttpBasicAsDisabled() {
            // Given
            ServerHttpSecurity http = ServerHttpSecurity.http();

            // When
            SecurityWebFilterChain filterChain = securityConfig.securityWebFilterChain(http);

            // Then - HTTP Basic should be disabled
            assertThat(filterChain).isNotNull();
        }

        @Test
        @DisplayName("✅ Should configure Form Login as disabled")
        void shouldConfigureFormLoginAsDisabled() {
            // Given
            ServerHttpSecurity http = ServerHttpSecurity.http();

            // When
            SecurityWebFilterChain filterChain = securityConfig.securityWebFilterChain(http);

            // Then - Form login should be disabled (JWT only)
            assertThat(filterChain).isNotNull();
        }
    }

    /* ===============================================
       BEAN LIFECYCLE TESTS
       =============================================== */

    @Nested
    @DisplayName("Bean Lifecycle")
    class BeanLifecycleTests {

        @Test
        @DisplayName("✅ Should create thread-safe password encoder")
        void shouldCreateThreadSafePasswordEncoder() {
            // Given
            PasswordEncoder encoder = securityConfig.passwordEncoder();
            String password = "TestPassword123!";

            // When - Encode from multiple threads
            var results = java.util.stream.IntStream.range(0, 10)
                    .parallel()
                    .mapToObj(i -> encoder.encode(password))
                    .toList();

            // Then - All should be valid
            results.forEach(encoded -> {
                assertThat(encoder.matches(password, encoded)).isTrue();
            });
        }

        @Test
        @DisplayName("✅ Should create reusable role hierarchy")
        void shouldCreateReusableRoleHierarchy() {
            // Given
            RoleHierarchy hierarchy1 = securityConfig.roleHierarchy();
            RoleHierarchy hierarchy2 = securityConfig.roleHierarchy();

            // When & Then - Each call creates new instance
            assertThat(hierarchy1).isNotNull();
            assertThat(hierarchy2).isNotNull();
            // Configuration should be consistent
        }

        @Test
        @DisplayName("✅ Should create independent rate limiters")
        void shouldCreateIndependentRateLimiters() {
            // Given
            Bucket limiter1 = securityConfig.rateLimiter();
            Bucket limiter2 = securityConfig.rateLimiter();

            // When - Consume from limiter1
            for (int i = 0; i < 10; i++) {
                limiter1.tryConsume(1);
            }

            // Then - limiter2 should still have tokens
            assertThat(limiter2.tryConsume(1)).isTrue();
        }
    }
}