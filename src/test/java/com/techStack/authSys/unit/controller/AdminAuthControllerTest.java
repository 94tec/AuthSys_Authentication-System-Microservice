package com.techStack.authSys.unit.controller;

import com.techStack.authSys.controller.admin.AdminAuthController;
import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.dto.response.BootstrapResult;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.AuthenticationOrchestrator;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.service.bootstrap.TransactionalBootstrapService;
import com.techStack.authSys.service.user.AdminService;
import com.techStack.authSys.service.verification.EmailVerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
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
 * Tests for AdminAuthController (Document 5)
 * Endpoint: /api/super-admin
 * Handles Super Admin and Admin operations
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AdminAuthController Tests - /api/super-admin")
class AdminAuthControllerTest {

    @Mock
    private AuthenticationOrchestrator authenticationOrchestrator;


    @Mock
    private TransactionalBootstrapService transactionalBootstrapService;

    @Mock
    private AdminService adminUserManagementService;

    @Mock
    private DeviceVerificationService deviceVerificationService;

    @Mock
    private EmailVerificationService emailVerificationService;

    @Mock
    private Clock clock;

    @Mock
    private ServerWebExchange exchange;

    @InjectMocks
    private AdminAuthController controller;

    private static final String SUPER_ADMIN_EMAIL = "superadmin@example.com";
    private static final String ADMIN_EMAIL = "admin@example.com";
    private static final String TEST_PASSWORD = "SecurePass123!";
    private static final String ADMIN_PHONE = "+1234567890";
    private static final String USER_AGENT = "Mozilla/5.0";
    private static final String CLIENT_IP = "192.168.1.1";
    private static final String DEVICE_FINGERPRINT = "device-fp-123";
    private static final Instant FIXED_TIME = Instant.parse("2026-02-14T10:00:00Z");

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(FIXED_TIME);
        when(clock.getZone()).thenReturn(ZoneId.systemDefault());

        when(deviceVerificationService.extractClientIp(any(ServerWebExchange.class)))
                .thenReturn(CLIENT_IP);
        when(deviceVerificationService.generateDeviceFingerprint(anyString(), anyString()))
                .thenReturn(DEVICE_FINGERPRINT);
    }

    /* =========================
       Super Admin Registration Tests
       ========================= */

    @Test
    @DisplayName("Should successfully register new super admin")
    void shouldRegisterNewSuperAdmin() {
        // Given
        BootstrapResult bootstrapResult = new BootstrapResult(
                true,      // created
                false,     // alreadyExists
                true,      // bootstrapMarkedComplete
                true,      // emailSent
                "user-123",
                "Super Admin created successfully",
                true       // requiresFirstTimeSetup
        );

        when(transactionalBootstrapService.createSuperAdminTransactionally(
                eq(SUPER_ADMIN_EMAIL), eq(ADMIN_PHONE)))
                .thenReturn(Mono.just(bootstrapResult));

        // When
        Mono<ResponseEntity<ApiResponse<BootstrapResult>>> result =
                controller.registerSuperAdmin(SUPER_ADMIN_EMAIL, ADMIN_PHONE);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().isSuccess()).isTrue();
                    assertThat(response.getBody().getData().created()).isTrue();
                    assertThat(response.getBody().getData().alreadyExists()).isFalse();
                    assertThat(response.getBody().getData().emailSent()).isTrue();
                })
                .verifyComplete();

        verify(transactionalBootstrapService).createSuperAdminTransactionally(
                SUPER_ADMIN_EMAIL, ADMIN_PHONE);
    }

    @Test
    @DisplayName("Should return OK when super admin already exists")
    void shouldReturnOkWhenSuperAdminExists() {
        // Given
        BootstrapResult bootstrapResult = new BootstrapResult(
                false,     // created
                true,      // alreadyExists
                true,      // bootstrapMarkedComplete
                false,     // emailSent
                "existing-user-123",
                "Super Admin already exists",
                false      // requiresFirstTimeSetup
        );

        when(transactionalBootstrapService.createSuperAdminTransactionally(
                eq(SUPER_ADMIN_EMAIL), eq(ADMIN_PHONE)))
                .thenReturn(Mono.just(bootstrapResult));

        // When
        Mono<ResponseEntity<ApiResponse<BootstrapResult>>> result =
                controller.registerSuperAdmin(SUPER_ADMIN_EMAIL, ADMIN_PHONE);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().getData().alreadyExists()).isTrue();
                })
                .verifyComplete();
    }

    /* =========================
       Admin Login Tests
       ========================= */

    @Test
    @DisplayName("Should successfully login super admin")
    void shouldLoginSuperAdmin() {
        // Given
        LoginRequest loginRequest = new LoginRequest(SUPER_ADMIN_EMAIL, TEST_PASSWORD);
        User superAdmin = createSuperAdmin();
        AuthResult authResult = createAuthResult(superAdmin);

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

                    assertThat(authResponse.getUserInfo().getRoles()).contains("SUPER_ADMIN");
                })
                .verifyComplete();

        verify(authenticationOrchestrator).authenticate(
                eq(SUPER_ADMIN_EMAIL), eq(TEST_PASSWORD), eq(CLIENT_IP), any(Instant.class),
                eq(DEVICE_FINGERPRINT), eq(USER_AGENT), eq("LOGIN"), eq(controller), eq(Set.of())
        );
    }

    @Test
    @DisplayName("Should successfully login admin")
    void shouldLoginAdmin() {
        // Given
        LoginRequest loginRequest = new LoginRequest(ADMIN_EMAIL, TEST_PASSWORD);
        User admin = createAdmin();
        AuthResult authResult = createAuthResult(admin);

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

                    assertThat(authResponse.getUserInfo().getRoles()).contains("ADMIN");
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("Should handle admin login failure")
    void shouldHandleAdminLoginFailure() {
        // Given
        LoginRequest loginRequest = new LoginRequest(ADMIN_EMAIL, "wrong-password");

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
       Admin User Registration Tests
       ========================= */

    @Test
    @DisplayName("Should successfully register new admin user")
    void shouldRegisterNewAdmin() {
        // Given
        UserRegistrationDTO adminDto = new UserRegistrationDTO();
        adminDto.setEmail(ADMIN_EMAIL);
        adminDto.setPassword(TEST_PASSWORD);
        adminDto.setFirstName("Admin");
        adminDto.setLastName("User");

        User newAdmin = createAdmin();

        when(adminUserManagementService.createAdminUser(
                any(UserRegistrationDTO.class), any(ServerWebExchange.class),
                anyString(), anyString()))
                .thenReturn(Mono.just(newAdmin));

        // When
        Mono<ResponseEntity<ApiResponse<String>>> result = controller.registerAdmin(
                adminDto, exchange
        );

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().isSuccess()).isTrue();
                    assertThat(response.getBody().getMessage()).contains("Admin user created successfully");
                })
                .verifyComplete();

        verify(adminUserManagementService).createAdminUser(
                any(UserRegistrationDTO.class), any(ServerWebExchange.class),
                eq(CLIENT_IP), eq(DEVICE_FINGERPRINT)
        );
    }

    /* =========================
       Permission Verification Tests
       ========================= */

    @Test
    @DisplayName("Should include all admin permissions in login response")
    void shouldIncludeAdminPermissions() {
        // Given
        LoginRequest loginRequest = new LoginRequest(SUPER_ADMIN_EMAIL, TEST_PASSWORD);
        User superAdmin = createSuperAdmin();

        // Add additional permissions to user (User model uses List<String> additionalPermissions)
        superAdmin.setAdditionalPermissions(java.util.List.of(
                Permissions.READ.name(),
                Permissions.WRITE.name(),
                Permissions.DELETE.name()
        ));

        AuthResult authResult = createAuthResult(superAdmin);

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
                    assertThat(authResponse.getPermissions()).isNotEmpty();

                    assertThat(authResponse.getPermissions().size()).isGreaterThan(0);
                })
                .verifyComplete();
    }

    /* =========================
       Helper Methods
       ========================= */

    private User createSuperAdmin() {
        User user = new User();
        user.setId("superadmin-" + System.currentTimeMillis());
        user.setEmail(SUPER_ADMIN_EMAIL);
        user.setFirstName("Super");
        user.setLastName("Admin");
        user.setRoleNames(java.util.List.of(Roles.SUPER_ADMIN.name()));
        user.setEmailVerified(true);
        user.setEnabled(true);
        user.setForcePasswordChange(false);
        return user;
    }

    private User createAdmin() {
        User user = new User();
        user.setId("admin-" + System.currentTimeMillis());
        user.setEmail(ADMIN_EMAIL);
        user.setFirstName("Admin");
        user.setLastName("User");
        user.setRoleNames(java.util.List.of(Roles.ADMIN.name()));
        user.setEmailVerified(true);
        user.setEnabled(true);
        user.setForcePasswordChange(false);
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
}