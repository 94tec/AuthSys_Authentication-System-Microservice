package com.techStack.authSys.unit.service.auth;

import com.techStack.authSys.config.core.LoginOtpProperties;
import com.techStack.authSys.dto.response.LoginOtpResponse;
import com.techStack.authSys.dto.response.LoginResponse;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.AuthenticationService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.auth.LoginOtpService;
import com.techStack.authSys.service.token.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Tests for AuthenticationService priority-based login flow
 * Tests three priorities:
 * 1. First-time login (force password change)
 * 2. OTP verification (2FA)
 * 3. Normal login
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService Tests")
class AuthenticationServiceTest {

    @Mock
    private FirebaseServiceAuth firebaseServiceAuth;

    @Mock
    private JwtService jwtService;

    @Mock
    private LoginOtpService loginOtpService;

    @Mock
    private Clock clock;

    @InjectMocks
    private AuthenticationService authenticationService;
    private LoginOtpProperties loginOtpProperties;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "SecurePass123!";
    private static final Instant FIXED_TIME = Instant.parse("2026-02-14T10:00:00Z");

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(FIXED_TIME);
        when(clock.getZone()).thenReturn(ZoneId.systemDefault());
    }

    /* =========================
       Priority 1: First-Time Login Tests
       ========================= */

    @Test
    @DisplayName("Priority 1: Should return temporary token for first-time login")
    void shouldHandleFirstTimeLogin() {
        // Given
        User firstTimeUser = createUserWithForcePasswordChange();
        String tempToken = "temp-token-123";

        when(firebaseServiceAuth.validateCredentials(TEST_EMAIL, TEST_PASSWORD)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(firstTimeUser));
        when(jwtService.generateTemporaryToken(firstTimeUser.getId())).thenReturn(tempToken);

        // When
        Mono<LoginResponse> result = authenticationService.login(TEST_EMAIL, TEST_PASSWORD,null, null, null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.firstTimeLogin()).isTrue();
                    assertThat(response.temporaryToken()).isEqualTo(tempToken);
                    assertThat(response.requiresOtp()).isFalse();
                    assertThat(response.accessToken()).isNull();
                    assertThat(response.message()).contains("First-time login");
                })
                .verifyComplete();

        verify(jwtService).generateTemporaryToken(firstTimeUser.getId());
        verify(loginOtpService, never()).generateAndSendLoginOtp(any());
        verify(jwtService, never()).generateAccessToken(any());
    }

    @Test
    @DisplayName("Priority 1: Should skip OTP even if phone verified for first-time user")
    void shouldSkipOtpForFirstTimeUser() {
        // Given
        User firstTimeUserWithPhone = createUserWithForcePasswordChange();
        firstTimeUserWithPhone.setPhoneVerified(true); // Phone verified but still first-time

        when(firebaseServiceAuth.validateCredentials(TEST_EMAIL, TEST_PASSWORD)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(firstTimeUserWithPhone));
        when(jwtService.generateTemporaryToken(anyString())).thenReturn("temp-token");

        // When
        Mono<LoginResponse> result = authenticationService.login(TEST_EMAIL, TEST_PASSWORD,null,null,null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.firstTimeLogin()).isTrue();
                    assertThat(response.requiresOtp()).isFalse();
                })
                .verifyComplete();

        verify(loginOtpService, never()).generateAndSendLoginOtp(any());
    }

    /* =========================
       Priority 2: OTP Login Tests
       ========================= */

    @Test
    @DisplayName("Priority 2: Should send OTP for user with verified phone")
    void shouldSendOtpForVerifiedPhone() {
        // Given
        User userWithPhone = createUserWithVerifiedPhone();
        LoginOtpResponse otpResponse = LoginOtpResponse.otpSent(
                "otp-temp-token",
                "user-123",
                "OTP sent to your phone"
        );


        when(firebaseServiceAuth.validateCredentials(TEST_EMAIL, TEST_PASSWORD)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(userWithPhone));
        when(loginOtpService.generateAndSendLoginOtp(userWithPhone)).thenReturn(Mono.just(otpResponse));

        // When
        Mono<LoginResponse> result = authenticationService.login(TEST_EMAIL, TEST_PASSWORD, null,null,null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.requiresOtp()).isTrue();
                    assertThat(response.firstTimeLogin()).isFalse();
                    assertThat(response.temporaryToken()).isEqualTo("otp-temp-token");
                    assertThat(response.accessToken()).isNull();
                    assertThat(response.message()).contains("OTP sent");
                })
                .verifyComplete();

        verify(loginOtpService).generateAndSendLoginOtp(userWithPhone);
        verify(jwtService, never()).generateAccessToken(any());
    }

    @Test
    @DisplayName("Priority 2: Should handle rate-limited OTP")
    void shouldHandleRateLimitedOtp() {
        // Given
        User userWithPhone = createUserWithVerifiedPhone();
        LoginOtpResponse otpResponse = LoginOtpResponse.otpSent(
                "otp-temp-token",
                "user-123",
                "OTP sent to your phone"
        );


        when(firebaseServiceAuth.validateCredentials(TEST_EMAIL, TEST_PASSWORD)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(userWithPhone));
        when(loginOtpService.generateAndSendLoginOtp(userWithPhone)).thenReturn(Mono.just(otpResponse));

        // When
        Mono<LoginResponse> result = authenticationService.login(TEST_EMAIL, TEST_PASSWORD,null,null,null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.message()).contains("Too many OTP requests");
                })
                .verifyComplete();
    }

    /* =========================
       Priority 3: Normal Login Tests
       ========================= */

    @Test
    @DisplayName("Priority 3: Should provide full access for user without verified phone")
    void shouldProvideFullAccessWithoutPhone() {
        // Given
        User userWithoutPhone = createUserWithoutPhone();
        String accessToken = "access-token-123";
        String refreshToken = "refresh-token-123";

        when(firebaseServiceAuth.validateCredentials(TEST_EMAIL, TEST_PASSWORD)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(userWithoutPhone));
        when(jwtService.generateAccessToken(userWithoutPhone)).thenReturn(accessToken);
        when(jwtService.generateRefreshToken(userWithoutPhone.getId())).thenReturn(refreshToken);

        // When
        Mono<LoginResponse> result = authenticationService.login(TEST_EMAIL, TEST_PASSWORD,null,null,null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.requiresOtp()).isFalse();
                    assertThat(response.firstTimeLogin()).isFalse();
                    assertThat(response.accessToken()).isEqualTo(accessToken);
                    assertThat(response.refreshToken()).isEqualTo(refreshToken);
                    assertThat(response.message()).contains("Login successful");
                })
                .verifyComplete();

        verify(jwtService).generateAccessToken(userWithoutPhone);
        verify(jwtService).generateRefreshToken(userWithoutPhone.getId());
        verify(loginOtpService, never()).generateAndSendLoginOtp(any());
    }

    @Test
    @DisplayName("Priority 3: Should provide full access when OTP disabled globally")
    void shouldProvideFullAccessWhenOtpDisabled() {
        // Given
        User userWithPhone = createUserWithVerifiedPhone();
        String accessToken = "access-token-456";
        String refreshToken = "refresh-token-456";

        // Simulate OTP disabled in configuration
        when(loginOtpProperties.isEnabled()).thenReturn(false);


        when(firebaseServiceAuth.validateCredentials(TEST_EMAIL, TEST_PASSWORD)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.findByEmail(TEST_EMAIL)).thenReturn(Mono.just(userWithPhone));
        when(jwtService.generateAccessToken(userWithPhone)).thenReturn(accessToken);
        when(jwtService.generateRefreshToken(userWithPhone.getId())).thenReturn(refreshToken);

        // When
        Mono<LoginResponse> result = authenticationService.login(TEST_EMAIL, TEST_PASSWORD,null,null,null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.requiresOtp()).isFalse();
                    assertThat(response.accessToken()).isNotNull();
                })
                .verifyComplete();

        verify(loginOtpService, never()).generateAndSendLoginOtp(any());
    }

    /* =========================
       Error Handling Tests
       ========================= */

    @Test
    @DisplayName("Should handle invalid credentials")
    void shouldHandleInvalidCredentials() {
        // Given
        when(firebaseServiceAuth.validateCredentials(TEST_EMAIL, "wrong-password"))
                .thenReturn(Mono.error(new RuntimeException("Invalid credentials")));

        // When
        Mono<LoginResponse> result = authenticationService.login(TEST_EMAIL, "wrong-password",null,null,null);

        // Then
        StepVerifier.create(result)
                .expectErrorMessage("Invalid credentials")
                .verify();

        verify(firebaseServiceAuth, never()).findByEmail(anyString());
    }

    @Test
    @DisplayName("Should handle user not found")
    void shouldHandleUserNotFound() {
        // Given
        when(firebaseServiceAuth.validateCredentials(TEST_EMAIL, TEST_PASSWORD)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.findByEmail(TEST_EMAIL))
                .thenReturn(Mono.error(new RuntimeException("User not found")));

        // When
        Mono<LoginResponse> result = authenticationService.login(TEST_EMAIL, TEST_PASSWORD,null,null,null);

        // Then
        StepVerifier.create(result)
                .expectErrorMessage("User not found")
                .verify();
    }

    /* =========================
       Logout Tests
       ========================= */

    @Test
    @DisplayName("Should successfully logout user")
    void shouldLogoutUser() {
        // Given
        String userId = "user-123";

        // When
        Mono<Void> result = authenticationService.logout(userId);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        // Note: Current implementation is empty, but test verifies it completes
    }

    /* =========================
       Helper Methods
       ========================= */

    private User createUserWithForcePasswordChange() {
        User user = new User();
        user.setId("user-123");
        user.setEmail(TEST_EMAIL);
        user.setRoleNames(java.util.List.of(Roles.USER.name()));
        user.setForcePasswordChange(true);
        user.setPhoneVerified(false);
        return user;
    }

    private User createUserWithVerifiedPhone() {
        User user = new User();
        user.setId("user-456");
        user.setEmail(TEST_EMAIL);
        user.setRoleNames(java.util.List.of(Roles.USER.name()));
        user.setForcePasswordChange(false);
        user.setPhoneVerified(true);
        return user;
    }

    private User createUserWithoutPhone() {
        User user = new User();
        user.setId("user-789");
        user.setEmail(TEST_EMAIL);
        user.setRoleNames(java.util.List.of(Roles.USER.name()));
        user.setForcePasswordChange(false);
        user.setPhoneVerified(false);
        return user;
    }
}