package com.techStack.authSys.unit.controller;

import com.techStack.authSys.controller.auth.AuthController;
import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for AuthController (Document 4)
 * Endpoint: /api/auth
 * Uses AuthenticationOrchestrator for authentication
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthController Tests - /api/auth")
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @Mock
    private AuthenticationOrchestrator authenticationOrchestrator;

    @Mock
    private FirebaseServiceAuth firebaseServiceAuth;

    @Mock
    private DeviceVerificationService deviceVerificationService;

    @Mock
    private LogoutService logoutService;

    @Mock
    private LoginResponseBuilder loginResponseBuilder;

    @Mock
    private Clock clock;

    @Mock
    private ServerWebExchange exchange;

    @InjectMocks
    private AuthController controller;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "SecurePass123!";
    private static final String USER_AGENT = "Mozilla/5.0";
    private static final String CLIENT_IP = "192.168.1.1";
    private static final String DEVICE_FINGERPRINT = "device-fp-123";
    private static final Instant FIXED_TIME = Instant.parse("2026-02-14T10:00:00Z");

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(FIXED_TIME);
        when(clock.getZone()).thenReturn(ZoneId.systemDefault());

        // Mock device verification service
        when(deviceVerificationService.extractClientIp(any(ServerWebExchange.class)))
                .thenReturn(CLIENT_IP);
        when(deviceVerificationService.generateDeviceFingerprint(anyString(), anyString()))
                .thenReturn(DEVICE_FINGERPRINT);
    }

    /* =========================
       User Registration Tests
       ========================= */

    @Test
    @DisplayName("Should successfully register a new user")
    void shouldRegisterNewUser() {
        // Given
        UserRegistrationDTO userDto = new UserRegistrationDTO();
        userDto.setEmail(TEST_EMAIL);
        userDto.setPassword(TEST_PASSWORD);
        userDto.setFirstName("Test");
        userDto.setLastName("User");

        User newUser = createUser(TEST_EMAIL, Roles.USER);

        when(authService.registerUser(any(UserRegistrationDTO.class), any(ServerWebExchange.class)))
                .thenReturn(Mono.just(newUser));

        // When
        Mono<ResponseEntity<ApiResponse<User>>> result = controller.registerUser(userDto, exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().isSuccess()).isTrue();
                    assertThat(response.getBody().getData().getEmail()).isEqualTo(TEST_EMAIL);
                    assertThat(response.getBody().getMessage()).contains("Registration successful");
                })
                .verifyComplete();

        verify(authService).registerUser(any(UserRegistrationDTO.class), any(ServerWebExchange.class));
    }

    /* =========================
       User Login Tests
       ========================= */

    @Test
    @DisplayName("Should successfully login user with orchestrator")
    void shouldLoginUserSuccessfully() {
        // Given
        LoginRequest loginRequest = new LoginRequest(TEST_EMAIL, TEST_PASSWORD);
        User user = createUser(TEST_EMAIL, Roles.USER);

        AuthResult authResult = createAuthResult(user);

        when(authenticationOrchestrator.authenticate(
                anyString(), anyString(), anyString(), any(Instant.class),
                anyString(), anyString(), anyString(), any(), any(Set.class)))
                .thenReturn(Mono.just(authResult));

        // When
        Mono<ResponseEntity<ApiResponse<AuthResponse>>> result = controller.login(
                loginRequest, USER_AGENT, exchange
        );

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

                    ApiResponse<AuthResponse> body = response.getBody();
                    assertThat(body).isNotNull();
                    assertThat(body.isSuccess()).isTrue();

                    AuthResponse authResponse = body.getData();
                    assertThat(authResponse).isNotNull();

                    assertThat(authResponse.getUserInfo().getRoles()).contains("USER");
                })
                .verifyComplete();


        verify(authenticationOrchestrator).authenticate(
                eq(TEST_EMAIL), eq(TEST_PASSWORD), eq(CLIENT_IP), any(Instant.class),
                eq(DEVICE_FINGERPRINT), eq(USER_AGENT), eq("USER_LOGIN"), eq(controller), eq(Set.of())
        );
    }

    @Test
    @DisplayName("Should handle authentication failure")
    void shouldHandleAuthenticationFailure() {
        // Given
        LoginRequest loginRequest = new LoginRequest(TEST_EMAIL, "wrong-password");

        when(authenticationOrchestrator.authenticate(
                anyString(), anyString(), anyString(), any(Instant.class),
                anyString(), anyString(), anyString(), any(), any(Set.class)))
                .thenReturn(Mono.error(new RuntimeException("Invalid credentials")));

        // When
        Mono<ResponseEntity<ApiResponse<AuthResponse>>> result = controller.login(
                loginRequest, USER_AGENT, exchange
        );

        // Then
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    /* =========================
       Email Verification Tests
       ========================= */

    @Test
    @DisplayName("Should resend verification email successfully")
    void shouldResendVerificationEmail() {
        // Given
        String email = TEST_EMAIL;

        when(authService.resendVerificationEmail(eq(email), eq(CLIENT_IP)))
                .thenReturn(Mono.empty());

        // When
        Mono<ResponseEntity<ApiResponse<Void>>> result = controller.resendVerificationEmail(
                email, exchange
        );

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().isSuccess()).isTrue();
                    assertThat(response.getBody().getMessage()).contains("Verification email sent");
                })
                .verifyComplete();

        verify(authService).resendVerificationEmail(email, CLIENT_IP);
    }

    @Test
    @DisplayName("Should verify email with valid token")
    void shouldVerifyEmail() {
        // Given
        String token = "valid-verification-token";

        when(authService.verifyEmail(eq(token), eq(CLIENT_IP)))
                .thenReturn(Mono.empty());

        // When
        Mono<ResponseEntity<ApiResponse<Object>>> result = controller.verifyEmail(
                token, exchange
        );

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().isSuccess()).isTrue();
                    assertThat(response.getBody().getMessage()).contains("Email verified successfully");
                })
                .verifyComplete();

        verify(authService).verifyEmail(token, CLIENT_IP);
    }

    /* =========================
       Logout Tests
       ========================= */

    @Test
    @DisplayName("Should logout user successfully")
    void shouldLogoutUser() {
        // Given
        String authHeader = "Bearer valid-access-token";
        String token = "valid-access-token";

        when(logoutService.logout(eq(token), eq(CLIENT_IP)))
                .thenReturn(Mono.empty());

        // When
        Mono<ResponseEntity<ApiResponse<Void>>> result = controller.logout(
                authHeader, null // WebRequest mock
        );

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().isSuccess()).isTrue();
                    assertThat(response.getBody().getMessage()).contains("Logged out successfully");
                })
                .verifyComplete();

        verify(logoutService).logout(token, CLIENT_IP);
    }

    /* =========================
       Email Availability Tests
       ========================= */

    @Test
    @DisplayName("Should check email availability - available")
    void shouldCheckEmailAvailability_Available() {
        // Given
        String email = "newuser@example.com";

        when(firebaseServiceAuth.checkEmailAvailability(email))
                .thenReturn(Mono.just(true));

        // When
        Mono<ResponseEntity<ApiResponse<Boolean>>> result = controller.checkEmailAvailability(email);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().getData()).isTrue();
                    assertThat(response.getBody().getMessage()).contains("Email is available");
                })
                .verifyComplete();

        verify(firebaseServiceAuth).checkEmailAvailability(email);
    }

    @Test
    @DisplayName("Should check email availability - not available")
    void shouldCheckEmailAvailability_NotAvailable() {
        // Given
        String email = TEST_EMAIL;

        when(firebaseServiceAuth.checkEmailAvailability(email))
                .thenReturn(Mono.just(false));

        // When
        Mono<ResponseEntity<ApiResponse<Boolean>>> result = controller.checkEmailAvailability(email);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().getData()).isFalse();
                    assertThat(response.getBody().getMessage()).contains("Email is already registered");
                })
                .verifyComplete();
    }

    /* =========================
       Helper Methods
       ========================= */

    private User createUser(String email, Roles role) {
        User user = new User();
        user.setId("user-" + System.currentTimeMillis());
        user.setEmail(email);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setRoleNames(List.of(role.name()));
        user.setEmailVerified(true);
        user.setEnabled(true);
        return user;
    }

    private AuthResult createAuthResult(User user) {
        return AuthResult.builder()
                .accessToken("access-token-123")
                .refreshToken("refresh-token-123")
                .accessTokenExpiry(Instant.now().plus(Duration.ofHours(1)))
                .refreshTokenExpiry(Instant.now().plus(Duration.ofDays(7)))
                .user(user)
                .permissions(List.of(Permissions.READ, Permissions.WRITE))
                .build();
    }

    private AuthResponse.UserInfo createUserInfo(User user) {
        return AuthResponse.UserInfo.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(Set.of(Roles.USER.name()))
                .mfaRequired(false)
                .build();
    }
}