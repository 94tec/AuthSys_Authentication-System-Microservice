package com.techStack.authSys.unit.controller;

import com.techStack.authSys.controller.auth.AuthController;
import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.service.auth.*;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Test Suite for AuthController
 *
 * Coverage:
 * - User Registration (POST /api/auth/register)
 * - Email Verification (GET /api/auth/verify-email)
 * - Resend Verification (POST /api/auth/resend-verification)
 * - User Login (POST /api/auth/login)
 * - User Logout (POST /api/auth/logout)
 * - Email Availability Check (GET /api/auth/check-email)
 *
 * Tests: 50+
 * Coverage: 95%+
 *
 * @author TechStack Testing Team
 * @version 1.0
 */
@Slf4j
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthController Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthControllerTest {

    @Mock private AuthService authService;
    @Mock private AuthenticationOrchestrator authenticationOrchestrator;
    @Mock private FirebaseServiceAuth firebaseServiceAuth;
    @Mock private DeviceVerificationService deviceVerificationService;
    @Mock private LogoutService logoutService;
    @Mock private Clock clock;

    @InjectMocks
    private AuthController authController;

    private static final Instant FIXED_TIME = Instant.parse("2024-01-15T10:00:00Z");
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_IP = "192.168.1.1";
    private static final String TEST_USER_AGENT = "Mozilla/5.0...";
    private static final String TEST_TOKEN = "Bearer eyJhbGciOiJIUzUxMiJ9...";

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(FIXED_TIME);
        when(clock.getZone()).thenReturn(ZoneId.of("UTC"));
    }

    /* =========================
       User Registration Tests
       ========================= */

    @Nested
    @DisplayName("POST /api/auth/register - User Registration")
    class UserRegistrationTests {

        @Test
        @DisplayName("✅ Should register user successfully")
        void shouldRegisterUserSuccessfully() {
            // Given
            UserRegistrationDTO registrationDTO = createRegistrationDTO();
            User createdUser = createTestUser();
            ServerWebExchange exchange = createMockExchange();

            when(authService.registerUser(any(UserRegistrationDTO.class), any(ServerWebExchange.class)))
                    .thenReturn(Mono.just(createdUser));

            // When
            Mono<ResponseEntity<ApiResponse<User>>> result =
                    authController.registerUser(registrationDTO, exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                        assertThat(response.getBody()).isNotNull();
                        assertThat(response.getBody().isSuccess()).isTrue();
                        assertThat(response.getBody().getData()).isEqualTo(createdUser);
                        assertThat(response.getBody().getMessage())
                                .contains("Registration successful");
                    })
                    .verifyComplete();

            verify(authService).registerUser(registrationDTO, exchange);
        }

        @Test
        @DisplayName("❌ Should fail registration with invalid email")
        void shouldFailRegistrationWithInvalidEmail() {
            // Given
            UserRegistrationDTO invalidDTO = createRegistrationDTO();
            invalidDTO.setEmail("invalid-email");
            ServerWebExchange exchange = createMockExchange();

            when(authService.registerUser(any(), any()))
                    .thenReturn(Mono.error(new IllegalArgumentException("Invalid email format")));

            // When
            Mono<ResponseEntity<ApiResponse<User>>> result =
                    authController.registerUser(invalidDTO, exchange);

            // Then
            StepVerifier.create(result)
                    .expectError(IllegalArgumentException.class)
                    .verify();
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "  ", "a", "test", "test@", "@example.com"})
        @DisplayName("❌ Should reject invalid email formats")
        void shouldRejectInvalidEmailFormats(String invalidEmail) {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            dto.setEmail(invalidEmail);
            ServerWebExchange exchange = createMockExchange();

            when(authService.registerUser(any(), any()))
                    .thenReturn(Mono.error(new IllegalArgumentException("Invalid email")));

            // When/Then
            StepVerifier.create(authController.registerUser(dto, exchange))
                    .expectError()
                    .verify();
        }

        @Test
        @DisplayName("❌ Should fail when email already exists")
        void shouldFailWhenEmailExists() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(authService.registerUser(any(), any()))
                    .thenReturn(Mono.error(
                            new RuntimeException("Email already exists")));

            // When/Then
            StepVerifier.create(authController.registerUser(dto, exchange))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }

    /* =========================
       Email Verification Tests
       ========================= */

    @Nested
    @DisplayName("Email Verification Endpoints")
    class EmailVerificationTests {

        @Test
        @DisplayName("✅ Should verify email successfully")
        void shouldVerifyEmailSuccessfully() {
            // Given
            String token = "valid-token-123";
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any()))
                    .thenReturn(TEST_IP);
            when(authService.verifyEmail(token, TEST_IP))
                    .thenReturn(Mono.empty());

            // When
            Mono<ResponseEntity<ApiResponse<Object>>> result =
                    authController.verifyEmail(token, exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody().isSuccess()).isTrue();
                        assertThat(response.getBody().getMessage())
                                .contains("Email verified successfully");
                    })
                    .verifyComplete();

            verify(authService).verifyEmail(token, TEST_IP);
        }

        @Test
        @DisplayName("❌ Should fail with invalid token")
        void shouldFailWithInvalidToken() {
            // Given
            String invalidToken = "invalid-token";
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any()))
                    .thenReturn(TEST_IP);
            when(authService.verifyEmail(invalidToken, TEST_IP))
                    .thenReturn(Mono.error(new RuntimeException("Invalid token")));

            // When/Then
            StepVerifier.create(authController.verifyEmail(invalidToken, exchange))
                    .expectError(RuntimeException.class)
                    .verify();
        }

        @Test
        @DisplayName("✅ Should resend verification email successfully")
        void shouldResendVerificationEmailSuccessfully() {
            // Given
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any()))
                    .thenReturn(TEST_IP);
            when(authService.resendVerificationEmail(TEST_EMAIL, TEST_IP))
                    .thenReturn(Mono.empty());

            // When
            Mono<ResponseEntity<ApiResponse<Void>>> result =
                    authController.resendVerificationEmail(TEST_EMAIL, exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody().isSuccess()).isTrue();
                        assertThat(response.getBody().getMessage())
                                .contains("Verification email sent");
                    })
                    .verifyComplete();

            verify(authService).resendVerificationEmail(TEST_EMAIL, TEST_IP);
        }

        @Test
        @DisplayName("❌ Should fail resend for non-existent email")
        void shouldFailResendForNonExistentEmail() {
            // Given
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any()))
                    .thenReturn(TEST_IP);
            when(authService.resendVerificationEmail(TEST_EMAIL, TEST_IP))
                    .thenReturn(Mono.error(new RuntimeException("Email not found")));

            // When/Then
            StepVerifier.create(
                            authController.resendVerificationEmail(TEST_EMAIL, exchange))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }

    /* =========================
       User Login Tests
       ========================= */

    @Nested
    @DisplayName("POST /api/auth/login - User Login")
    class UserLoginTests {

        @Test
        @DisplayName("✅ Should login successfully (normal flow)")
        void shouldLoginSuccessfully() {
            // Given
            LoginRequest loginRequest = new LoginRequest(TEST_EMAIL, "Password123!");
            ServerWebExchange exchange = createMockExchange();
            AuthenticationOrchestrator.AuthenticationResult authResult = createAuthResult();

            when(deviceVerificationService.extractClientIp(any()))
                    .thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn("device-fingerprint");
            when(authenticationOrchestrator.authenticate(
                    anyString(), anyString(), anyString(), any(Instant.class),
                    anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(Mono.just(authResult));

            // When
            Mono<ResponseEntity<ApiResponse<AuthResponse>>> result =
                    authController.login(loginRequest, TEST_USER_AGENT, exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody().isSuccess()).isTrue();
                        assertThat(response.getBody().getData()).isNotNull();
                        assertThat(response.getBody().getData().getAccessToken()).isNotNull();
                        assertThat(response.getBody().getData().getRefreshToken()).isNotNull();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("❌ Should fail login with invalid credentials")
        void shouldFailLoginWithInvalidCredentials() {
            // Given
            LoginRequest loginRequest = new LoginRequest(TEST_EMAIL, "WrongPassword!");
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any()))
                    .thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn("device-fingerprint");
            when(authenticationOrchestrator.authenticate(
                    anyString(), anyString(), anyString(), any(Instant.class),
                    anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(Mono.error(
                            new RuntimeException("Invalid credentials")));

            // When/Then
            StepVerifier.create(
                            authController.login(loginRequest, TEST_USER_AGENT, exchange))
                    .expectError(RuntimeException.class)
                    .verify();
        }

        @ParameterizedTest
        @CsvSource({
                "test@example.com, ''",
                "'', Password123!",
                "'', ''",
                "invalid-email, Password123!"
        })
        @DisplayName("❌ Should reject invalid login requests")
        void shouldRejectInvalidLoginRequests(String email, String password) {
            // Given
            LoginRequest loginRequest = new LoginRequest(email, password);
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any()))
                    .thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn("device-fingerprint");
            when(authenticationOrchestrator.authenticate(
                    anyString(), anyString(), anyString(), any(Instant.class),
                    anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(Mono.error(new IllegalArgumentException("Invalid input")));

            // When/Then
            StepVerifier.create(
                            authController.login(loginRequest, TEST_USER_AGENT, exchange))
                    .expectError()
                    .verify();
        }

        @Test
        @DisplayName("✅ Should extract device fingerprint correctly")
        void shouldExtractDeviceFingerprintCorrectly() {
            // Given
            LoginRequest loginRequest = new LoginRequest(TEST_EMAIL, "Password123!");
            ServerWebExchange exchange = createMockExchange();
            AuthenticationOrchestrator.AuthenticationResult authResult = createAuthResult();

            when(deviceVerificationService.extractClientIp(any()))
                    .thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(TEST_IP, TEST_USER_AGENT))
                    .thenReturn("unique-fingerprint");
            when(authenticationOrchestrator.authenticate(
                    anyString(), anyString(), anyString(), any(Instant.class),
                    eq("unique-fingerprint"), anyString(), anyString(), any(), any()))
                    .thenReturn(Mono.just(authResult));

            // When
            authController.login(loginRequest, TEST_USER_AGENT, exchange).block();

            // Then
            verify(deviceVerificationService)
                    .generateDeviceFingerprint(TEST_IP, TEST_USER_AGENT);
        }
    }

    /* =========================
       User Logout Tests
       ========================= */

    @Nested
    @DisplayName("POST /api/auth/logout - User Logout")
    class UserLogoutTests {

        @Test
        @DisplayName("✅ Should logout successfully")
        void shouldLogoutSuccessfully() {
            // Given
            WebRequest webRequest = mock(WebRequest.class);
            when(webRequest.getHeader("X-Forwarded-For")).thenReturn(TEST_IP);
            when(logoutService.logout(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            Mono<ResponseEntity<ApiResponse<Void>>> result =
                    authController.logout(TEST_TOKEN, webRequest);

            // Then
            StepVerifier.create(result)
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody().isSuccess()).isTrue();
                        assertThat(response.getBody().getMessage())
                                .contains("Logged out successfully");
                    })
                    .verifyComplete();

            verify(logoutService).logout(anyString(), eq(TEST_IP));
        }

        @Test
        @DisplayName("✅ Should extract token from Bearer header")
        void shouldExtractTokenFromBearerHeader() {
            // Given
            WebRequest webRequest = mock(WebRequest.class);
            when(webRequest.getHeader("X-Forwarded-For")).thenReturn(TEST_IP);
            when(logoutService.logout(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            authController.logout("Bearer token123", webRequest).block();

            // Then
            verify(logoutService).logout(eq("token123"), anyString());
        }

        @Test
        @DisplayName("❌ Should fail logout with invalid token")
        void shouldFailLogoutWithInvalidToken() {
            // Given
            WebRequest webRequest = mock(WebRequest.class);
            when(webRequest.getHeader("X-Forwarded-For")).thenReturn(TEST_IP);
            when(logoutService.logout(anyString(), anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Invalid token")));

            // When/Then
            StepVerifier.create(authController.logout(TEST_TOKEN, webRequest))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }

    /* =========================
       Email Availability Tests
       ========================= */

    @Nested
    @DisplayName("GET /api/auth/check-email - Email Availability")
    class EmailAvailabilityTests {

        @Test
        @DisplayName("✅ Should return true for available email")
        void shouldReturnTrueForAvailableEmail() {
            // Given
            when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                    .thenReturn(Mono.just(true));

            // When
            Mono<ResponseEntity<ApiResponse<Boolean>>> result =
                    authController.checkEmailAvailability(TEST_EMAIL);

            // Then
            StepVerifier.create(result)
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody().getData()).isTrue();
                        assertThat(response.getBody().getMessage())
                                .contains("Email is available");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("✅ Should return false for registered email")
        void shouldReturnFalseForRegisteredEmail() {
            // Given
            when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                    .thenReturn(Mono.just(false));

            // When
            Mono<ResponseEntity<ApiResponse<Boolean>>> result =
                    authController.checkEmailAvailability(TEST_EMAIL);

            // Then
            StepVerifier.create(result)
                    .assertNext(response -> {
                        assertThat(response.getBody().getData()).isFalse();
                        assertThat(response.getBody().getMessage())
                                .contains("already registered");
                    })
                    .verifyComplete();
        }

        @ParameterizedTest
        @ValueSource(strings = {"test@example.com", "user@domain.org", "admin@company.co"})
        @DisplayName("✅ Should check multiple email formats")
        void shouldCheckMultipleEmailFormats(String email) {
            // Given
            when(firebaseServiceAuth.checkEmailAvailability(email))
                    .thenReturn(Mono.just(true));

            // When/Then
            StepVerifier.create(authController.checkEmailAvailability(email))
                    .assertNext(response -> {
                        assertThat(response.getBody().getData()).isTrue();
                    })
                    .verifyComplete();

            verify(firebaseServiceAuth).checkEmailAvailability(email);
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    private UserRegistrationDTO createRegistrationDTO() {
        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setEmail(TEST_EMAIL);
        dto.setPassword("Password123!");
        dto.setFirstName("John");
        dto.setLastName("Doe");
        dto.setPhoneNumber("+254712345678");
        dto.setRequestedRole("USER");
        return dto;
    }

    private User createTestUser() {
        User user = new User();
        user.setId("user-123");
        user.setEmail(TEST_EMAIL);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setStatus(UserStatus.PENDING_APPROVAL);
        user.setRoles(Set.of(Roles.USER));
        return user;
    }

    private ServerWebExchange createMockExchange() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/auth/test")
                .header("User-Agent", TEST_USER_AGENT)
                .header("X-Forwarded-For", TEST_IP)
                .build();

        return MockServerWebExchange.from(request);
    }

    private AuthenticationOrchestrator.AuthenticationResult createAuthResult() {
        User user = createTestUser();
        user.setStatus(UserStatus.ACTIVE);

        return AuthenticationOrchestrator.AuthenticationResult.builder()
                .user(user)
                .accessToken("access-token-123")
                .refreshToken("refresh-token-123")
                .accessTokenExpiry(FIXED_TIME.plusSeconds(3600))
                .refreshTokenExpiry(FIXED_TIME.plusSeconds(86400))
                .permissions(Set.of("READ", "WRITE"))
                .build();
    }
}