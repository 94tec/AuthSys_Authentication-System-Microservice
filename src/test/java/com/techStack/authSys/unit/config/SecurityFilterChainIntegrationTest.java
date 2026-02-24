package com.techStack.authSys.unit.config;

import com.techStack.authSys.config.TestConfig;
import com.techStack.authSys.config.TestContainersConfig;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.token.JwtService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Set;

/**
 * Integration Tests for Security Filter Chain
 * 
 * Tests end-to-end security configuration with real filters
 * 
 * Coverage:
 * - Public endpoint access
 * - Protected endpoint authentication
 * - Role-based authorization
 * - Filter chain order
 * - First-time setup enforcement
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@Import({TestConfig.class, TestContainersConfig.class})
@ActiveProfiles("test")
@DisplayName("Security Filter Chain - Integration Tests")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SecurityFilterChainIntegrationTest {

    @Autowired
    private WebTestClient webClient;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private FirestoreUserRepository userRepository;

    private static final String TEST_USER_EMAIL = "test@example.com";
    private static final String SUPER_ADMIN_EMAIL = "superadmin@example.com";

    @BeforeEach
    void setUp() {
        // Clean up test users
        userRepository.findByEmail(TEST_USER_EMAIL)
                .flatMap(user -> userRepository.delete(user.getId()))
                .block();

        userRepository.findByEmail(SUPER_ADMIN_EMAIL)
                .flatMap(user -> userRepository.delete(user.getId()))
                .block();
    }

    /* ===============================================
       PUBLIC ENDPOINTS TESTS
       =============================================== */

    @Nested
    @DisplayName("Public Endpoints")
    class PublicEndpointsTests {

        @Test
        @Order(1)
        @DisplayName("✅ Should allow access to Swagger UI")
        void shouldAllowAccessToSwagger() {
            webClient.get()
                    .uri("/swagger-ui.html")
                    .exchange()
                    .expectStatus().isOk();
        }

        @Test
        @Order(2)
        @DisplayName("✅ Should allow access to health endpoint")
        void shouldAllowAccessToHealth() {
            webClient.get()
                    .uri("/actuator/health")
                    .exchange()
                    .expectStatus().isOk();
        }

        @Test
        @Order(3)
        @DisplayName("✅ Should allow access to login endpoint")
        void shouldAllowAccessToLogin() {
            webClient.post()
                    .uri("/api/auth/login")
                    .exchange()
                    .expectStatus().is4xxClientError(); // Bad request (no body)
        }
    }

    /* ===============================================
       PROTECTED ENDPOINTS TESTS
       =============================================== */

    @Nested
    @DisplayName("Protected Endpoints")
    class ProtectedEndpointsTests {

        @Test
        @DisplayName("❌ Should reject access without token")
        void shouldRejectAccessWithoutToken() {
            webClient.get()
                    .uri("/api/user/profile")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("❌ Should reject access with invalid token")
        void shouldRejectAccessWithInvalidToken() {
            webClient.get()
                    .uri("/api/user/profile")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer invalid.token")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("✅ Should allow access with valid token")
        void shouldAllowAccessWithValidToken() {
            // Given - Create user and generate token
            User user = createTestUser(Roles.USER);
            String token = jwtService.generateAccessToken(user);

            // When & Then
            webClient.get()
                    .uri("/api/user/profile")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isOk();
        }
    }

    /* ===============================================
       ROLE-BASED AUTHORIZATION TESTS
       =============================================== */

    @Nested
    @DisplayName("Role-Based Authorization")
    class RoleBasedAuthorizationTests {

        @Test
        @DisplayName("❌ USER should NOT access admin endpoints")
        void userShouldNotAccessAdminEndpoints() {
            // Given
            User user = createTestUser(Roles.USER);
            String token = jwtService.generateAccessToken(user);

            // When & Then
            webClient.get()
                    .uri("/api/admin/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isForbidden();
        }

        @Test
        @DisplayName("✅ ADMIN should access admin endpoints")
        void adminShouldAccessAdminEndpoints() {
            // Given
            User admin = createTestUser(Roles.ADMIN);
            String token = jwtService.generateAccessToken(admin);

            // When & Then
            webClient.get()
                    .uri("/api/admin/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isOk();
        }

        @Test
        @DisplayName("❌ ADMIN should NOT access super admin endpoints")
        void adminShouldNotAccessSuperAdminEndpoints() {
            // Given
            User admin = createTestUser(Roles.ADMIN);
            String token = jwtService.generateAccessToken(admin);

            // When & Then
            webClient.post()
                    .uri("/api/super-admin/create-admin")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isForbidden();
        }

        @Test
        @DisplayName("✅ SUPER_ADMIN should access all endpoints")
        void superAdminShouldAccessAllEndpoints() {
            // Given
            User superAdmin = createTestUser(Roles.SUPER_ADMIN);
            String token = jwtService.generateAccessToken(superAdmin);

            // When & Then - Should access admin endpoint
            webClient.get()
                    .uri("/api/admin/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isOk();

            // Should access super admin endpoint
            webClient.get()
                    .uri("/api/super-admin/system-config")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .exchange()
                    .expectStatus().isOk();
        }
    }

    /* ===============================================
       HELPER METHODS
       =============================================== */

    private User createTestUser(Roles role) {
        User user = new User();
        user.setId("test-" + System.currentTimeMillis());
        user.setEmail(TEST_USER_EMAIL);
        user.setRoles(Set.of(role));
        user.setEnabled(true);
        user.setForcePasswordChange(false);
        user.setPhoneVerified(true);

        return userRepository.save(user).block();
    }
}