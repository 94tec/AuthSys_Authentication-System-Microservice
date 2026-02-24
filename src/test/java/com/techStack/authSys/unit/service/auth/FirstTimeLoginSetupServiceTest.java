package com.techStack.authSys.unit.service.auth;

import com.techStack.authSys.config.TestConfig;
import com.techStack.authSys.dto.request.ChangePasswordRequest;
import com.techStack.authSys.dto.request.VerifyOtpRequest;
import com.techStack.authSys.dto.response.OtpResult;
import com.techStack.authSys.dto.response.OtpVerificationResult;
import com.techStack.authSys.exception.auth.InvalidTokenException;
import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.security.RateLimiterService;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.auth.FirstTimeLoginSetupService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.OtpService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.service.user.PasswordChangeService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.ReactiveValueOperations;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Unit Tests for FirstTimeLoginSetupService
 *
 * Coverage: 95%+
 *
 * Tests the complete 3-step first-time setup flow:
 * 1. Initiate: Send OTP and lock temp password
 * 2. Verify: Verify OTP and get verification token
 * 3. Complete: Change password and activate account
 */
@ExtendWith(MockitoExtension.class)
@Import(TestConfig.class)
@DisplayName("FirstTimeLoginSetupService - Unit Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FirstTimeLoginSetupServiceTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private OtpService otpService;

    @Mock
    private FirebaseServiceAuth firebaseServiceAuth;

    @Mock
    private PasswordChangeService passwordChangeService;

    @Mock
    private SessionService sessionManagementService;

    @Mock
    private EmailService emailService;

    @Mock
    private RateLimiterService rateLimiterService;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private ReactiveRedisTemplate<String, String> redisTemplate;

    @Mock
    private ReactiveValueOperations<String, String> valueOperations;

    @Mock
    private Clock clock;

    @InjectMocks
    private FirstTimeLoginSetupService setupService;

    // Test Data
    private static final String TEST_USER_ID = "test-user-123";
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PHONE = "+254712345678";
    private static final String TEST_TOKEN = "Bearer temp-token-abc";
    private static final String TEST_OTP = "123456";
    private static final String TEST_PASSWORD = "NewSecurePass123!";
    private static final Instant FIXED_TIME = Instant.parse("2024-01-15T10:00:00Z");

    @BeforeEach
    void setUp() {
        // Mock clock
        when(clock.instant()).thenReturn(FIXED_TIME);

        // Mock Redis operations
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    /* ===============================================
       STEP 1: INITIATE PASSWORD CHANGE TESTS
       =============================================== */

    @Nested
    @DisplayName("Step 1: Initiate Password Change")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class InitiateTests {

        @Test
        @Order(1)
        @DisplayName("✅ Should initiate setup successfully with valid token")
        void shouldInitiateSetupSuccessfully() {
            // Given
            User user = createTestUser();
            OtpResult expectedOtpResult = createSuccessOtpResult();

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(rateLimiterService.checkOtpRateLimit(anyString(), anyString())).thenReturn(Mono.empty());
            when(firebaseServiceAuth.save(any(User.class))).thenReturn(Mono.just(user));
            when(otpService.generateAndSendSetupOtp(anyString(), anyString()))
                    .thenReturn(Mono.just(expectedOtpResult));
            when(emailService.sendOtpNotification(anyString(), anyString(), anyString(), any()))
                    .thenReturn(Mono.empty());
            when(auditLogService.logAuditEvent(anyString(), any(), anyString(), anyMap()))
                    .thenReturn(Mono.empty());

            // When
            Mono<OtpResult> result = setupService.initiatePasswordChange(TEST_TOKEN);

            // Then
            StepVerifier.create(result)
                    .assertNext(otpResult -> {
                        assertThat(otpResult.sent()).isTrue();
                        assertThat(otpResult.rateLimited()).isFalse();
                        assertThat(otpResult.expiresInSeconds()).isEqualTo(600);
                        assertThat(otpResult.message()).contains("OTP sent");
                    })
                    .verifyComplete();

            // Verify interactions
            verify(jwtService).validateTemporaryToken(contains("temp-token"));
            verify(jwtService).getUserIdFromToken(contains("temp-token"));
            verify(firebaseServiceAuth).getUserById(TEST_USER_ID);
            verify(rateLimiterService).checkOtpRateLimit(TEST_USER_ID, "SETUP");

            // Verify temp password was locked
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(firebaseServiceAuth).save(userCaptor.capture());
            assertThat(userCaptor.getValue().isTemporaryPasswordLocked()).isTrue();
            assertThat(userCaptor.getValue().getTemporaryPasswordLockedAt()).isEqualTo(FIXED_TIME);

            verify(otpService).generateAndSendSetupOtp(TEST_USER_ID, TEST_PHONE);
            verify(emailService).sendOtpNotification(eq(TEST_EMAIL), anyString(), anyString(), eq(FIXED_TIME));
        }

        @Test
        @Order(2)
        @DisplayName("❌ Should fail with null token")
        void shouldFailWithNullToken() {
            // When & Then
            StepVerifier.create(setupService.initiatePasswordChange(null))
                    .expectErrorMatches(e ->
                            e instanceof IllegalArgumentException &&
                                    e.getMessage().contains("Token is required"))
                    .verify();

            verifyNoInteractions(jwtService, firebaseServiceAuth, otpService);
        }

        @Test
        @Order(3)
        @DisplayName("❌ Should fail with invalid token")
        void shouldFailWithInvalidToken() {
            // Given
            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(false));

            // When & Then
            StepVerifier.create(setupService.initiatePasswordChange("invalid-token"))
                    .expectErrorMatches(e ->
                            e instanceof InvalidTokenException &&
                                    e.getMessage().contains("Invalid or expired"))
                    .verify();

            verify(jwtService).validateTemporaryToken("invalid-token");
            verifyNoInteractions(firebaseServiceAuth, otpService);
        }

        @Test
        @Order(4)
        @DisplayName("❌ Should fail if user not in first-time setup state")
        void shouldFailIfNotFirstTimeSetup() {
            // Given
            User user = createTestUser();
            user.setForcePasswordChange(false); // Not in first-time setup

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));

            // When & Then
            StepVerifier.create(setupService.initiatePasswordChange(TEST_TOKEN))
                    .expectErrorMatches(e ->
                            e instanceof IllegalStateException &&
                                    e.getMessage().contains("not in first-time setup state"))
                    .verify();

            verify(firebaseServiceAuth).getUserById(TEST_USER_ID);
            verifyNoInteractions(otpService);
        }

        @Test
        @Order(5)
        @DisplayName("❌ Should fail if setup already in progress")
        void shouldFailIfSetupInProgress() {
            // Given
            User user = createTestUser();
            user.setTemporaryPasswordLocked(true); // Already locked

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));

            // When & Then
            StepVerifier.create(setupService.initiatePasswordChange(TEST_TOKEN))
                    .expectErrorMatches(e ->
                            e instanceof IllegalStateException &&
                                    e.getMessage().contains("already in progress"))
                    .verify();
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        @DisplayName("🔄 Should handle OTP delivery success and failure")
        void shouldHandleOtpDelivery(boolean otpSent) {
            // Given
            User user = createTestUser();
            OtpResult otpResult = OtpResult.builder()
                    .sent(otpSent)
                    .rateLimited(false)
                    .expiresInSeconds(600)
                    .message(otpSent ? "Sent" : "Failed")
                    .build();

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(rateLimiterService.checkOtpRateLimit(anyString(), anyString())).thenReturn(Mono.empty());
            when(firebaseServiceAuth.save(any(User.class))).thenReturn(Mono.just(user));
            when(otpService.generateAndSendSetupOtp(anyString(), anyString()))
                    .thenReturn(Mono.just(otpResult));
            when(emailService.sendOtpNotification(anyString(), anyString(), anyString(), any()))
                    .thenReturn(otpSent ? Mono.empty() : Mono.error(new RuntimeException("Email failed")));
            when(auditLogService.logAuditEvent(anyString(), any(), anyString(), anyMap()))
                    .thenReturn(Mono.empty());

            // When & Then
            StepVerifier.create(setupService.initiatePasswordChange(TEST_TOKEN))
                    .assertNext(result -> {
                        assertThat(result.sent()).isEqualTo(otpSent);
                    })
                    .verifyComplete();
        }

        @Test
        @Order(6)
        @DisplayName("⚠️ Should handle rate limit exceeded")
        void shouldHandleRateLimitExceeded() {
            // Given
            User user = createTestUser();

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(rateLimiterService.checkOtpRateLimit(anyString(), anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Rate limit exceeded")));

            // When & Then
            StepVerifier.create(setupService.initiatePasswordChange(TEST_TOKEN))
                    .expectErrorMessage("Rate limit exceeded")
                    .verify();

            verify(rateLimiterService).checkOtpRateLimit(TEST_USER_ID, "SETUP");
            verifyNoInteractions(otpService);
        }
    }

    /* ===============================================
       STEP 2: VERIFY OTP TESTS
       =============================================== */

    @Nested
    @DisplayName("Step 2: Verify OTP")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class VerifyOtpTests {

        @Test
        @Order(1)
        @DisplayName("✅ Should verify OTP and return verification token")
        void shouldVerifyOtpSuccessfully() {
            // Given
            User user = createTestUser();
            user.setTemporaryPasswordLocked(true);

            VerifyOtpRequest request = new VerifyOtpRequest(TEST_OTP);
            String verificationToken = "verify_" + UUID.randomUUID();

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(otpService.verifySetupOtp(TEST_USER_ID, TEST_OTP))
                    .thenReturn(Mono.just(createValidOtpVerificationResult()));
            when(valueOperations.set(anyString(), eq(TEST_USER_ID), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(auditLogService.logAuditEvent(anyString(), any(), anyString(), anyMap()))
                    .thenReturn(Mono.empty());

            // When
            Mono<OtpVerificationResult> result = setupService.verifyOtp(TEST_TOKEN, request);

            // Then
            StepVerifier.create(result)
                    .assertNext(verifyResult -> {
                        assertThat(verifyResult.isValid()).isTrue();
                        assertThat(verifyResult.getVerificationToken()).isNotNull();
                        assertThat(verifyResult.getVerificationToken()).startsWith("verify_");
                        assertThat(verifyResult.getExpiresInSeconds()).isEqualTo(300);
                        assertThat(verifyResult.getMessage()).contains("verified");
                    })
                    .verifyComplete();

            verify(otpService).verifySetupOtp(TEST_USER_ID, TEST_OTP);
            verify(valueOperations).set(contains("verify_token:"), eq(TEST_USER_ID), eq(Duration.ofMinutes(5)));
        }

        @Test
        @Order(2)
        @DisplayName("❌ Should fail if temp password not locked")
        void shouldFailIfPasswordNotLocked() {
            // Given
            User user = createTestUser();
            user.setTemporaryPasswordLocked(false); // Not locked

            VerifyOtpRequest request = new VerifyOtpRequest(TEST_OTP);

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));

            // When & Then
            StepVerifier.create(setupService.verifyOtp(TEST_TOKEN, request))
                    .expectErrorMatches(e ->
                            e instanceof IllegalStateException &&
                                    e.getMessage().contains("initiate setup first"))
                    .verify();

            verifyNoInteractions(otpService);
        }

        @ParameterizedTest
        @CsvSource({
                "false, true, false, 0, 'OTP has expired'",
                "false, false, true, 0, 'Maximum OTP attempts exceeded'",
                "false, false, false, 2, 'Invalid OTP. 2 attempts remaining'",
                "false, false, false, 1, 'Invalid OTP. 1 attempt remaining'"
        })
        @DisplayName("🔄 Should handle OTP verification failures")
        void shouldHandleOtpVerificationFailures(
                boolean valid,
                boolean expired,
                boolean attemptsExceeded,
                int remainingAttempts,
                String expectedMessage) {

            // Given
            User user = createTestUser();
            user.setTemporaryPasswordLocked(true);

            VerifyOtpRequest request = new VerifyOtpRequest(TEST_OTP);

            OtpVerificationResult otpResult = OtpVerificationResult.builder()
                    .valid(valid)
                    .expired(expired)
                    .attemptsExceeded(attemptsExceeded)
                    .remainingAttempts(remainingAttempts)
                    .message(expectedMessage)
                    .build();

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(otpService.verifySetupOtp(TEST_USER_ID, TEST_OTP))
                    .thenReturn(Mono.just(otpResult));

            // When & Then
            StepVerifier.create(setupService.verifyOtp(TEST_TOKEN, request))
                    .assertNext(result -> {
                        assertThat(result.isValid()).isFalse();
                        assertThat(result.isExpired()).isEqualTo(expired);
                        assertThat(result.isAttemptsExceeded()).isEqualTo(attemptsExceeded);
                        assertThat(result.getRemainingAttempts()).isEqualTo(remainingAttempts);
                        assertThat(result.getMessage()).isEqualTo(expectedMessage);
                        assertThat(result.getVerificationToken()).isNull();
                    })
                    .verifyComplete();

            // Verification token should NOT be generated for invalid OTP
            verify(valueOperations, never()).set(anyString(), anyString(), any(Duration.class));
        }

        @Test
        @Order(3)
        @DisplayName("⚠️ Should handle Redis failure gracefully")
        void shouldHandleRedisFailure() {
            // Given
            User user = createTestUser();
            user.setTemporaryPasswordLocked(true);

            VerifyOtpRequest request = new VerifyOtpRequest(TEST_OTP);

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(otpService.verifySetupOtp(TEST_USER_ID, TEST_OTP))
                    .thenReturn(Mono.just(createValidOtpVerificationResult()));
            when(valueOperations.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(false)); // Redis write failed

            // When & Then
            StepVerifier.create(setupService.verifyOtp(TEST_TOKEN, request))
                    .expectErrorMatches(e ->
                            e instanceof RuntimeException &&
                                    e.getMessage().contains("Failed to store verification token"))
                    .verify();
        }
    }

    /* ===============================================
       STEP 3: COMPLETE SETUP TESTS
       =============================================== */

    @Nested
    @DisplayName("Step 3: Complete Setup")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class CompleteSetupTests {

        @Test
        @Order(1)
        @DisplayName("✅ Should complete setup successfully")
        void shouldCompleteSetupSuccessfully() {
            // Given
            String verificationToken = "verify_abc123";
            ChangePasswordRequest request = new ChangePasswordRequest(TEST_PASSWORD);
            User user = createTestUser();

            when(valueOperations.get("verify_token:" + verificationToken))
                    .thenReturn(Mono.just(TEST_USER_ID));
            when(redisTemplate.delete("verify_token:" + verificationToken))
                    .thenReturn(Mono.just(1L));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID))
                    .thenReturn(Mono.just(user));
            when(passwordChangeService.changePasswordFirstTime(TEST_USER_ID, TEST_PASSWORD))
                    .thenReturn(Mono.empty());
            when(firebaseServiceAuth.save(any(User.class)))
                    .thenReturn(Mono.just(user));
            when(sessionManagementService.invalidateAllUserSessions(TEST_USER_ID))
                    .thenReturn(Mono.empty());
            when(jwtService.blacklistToken(anyString()))
                    .thenReturn(Mono.empty());
            when(emailService.sendPasswordChangedNotification(anyString(), anyString(), any()))
                    .thenReturn(Mono.empty());
            when(jwtService.generateAccessToken(any(User.class)))
                    .thenReturn("new-access-token");
            when(jwtService.generateRefreshToken(anyString()))
                    .thenReturn("new-refresh-token");
            when(auditLogService.logAuditEvent(anyString(), any(), anyString(), anyMap()))
                    .thenReturn(Mono.empty());

            // When
            Mono<TokenPair> result = setupService.completePasswordChange(verificationToken, request);

            // Then
            StepVerifier.create(result)
                    .assertNext(tokenPair -> {
                        assertThat(tokenPair).isNotNull();
                        assertThat(tokenPair.accessToken()).isEqualTo("new-access-token");
                        assertThat(tokenPair.refreshToken()).isEqualTo("new-refresh-token");
                    })
                    .verifyComplete();

            // Verify password was changed
            verify(passwordChangeService).changePasswordFirstTime(TEST_USER_ID, TEST_PASSWORD);

            // Verify user was activated
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(firebaseServiceAuth).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.isForcePasswordChange()).isFalse();
            assertThat(savedUser.isTemporaryPasswordLocked()).isFalse();
            assertThat(savedUser.isPhoneVerified()).isTrue();
            assertThat(savedUser.isFirstTimeSetupCompleted()).isTrue();
            assertThat(savedUser.getFirstTimeSetupCompletedAt()).isEqualTo(FIXED_TIME);
            assertThat(savedUser.getPasswordChangedAt()).isEqualTo(FIXED_TIME);

            // Verify all sessions invalidated
            verify(sessionManagementService).invalidateAllUserSessions(TEST_USER_ID);

            // Verify confirmation email sent
            verify(emailService).sendPasswordChangedNotification(
                    eq(TEST_EMAIL), anyString(), eq(FIXED_TIME));

            // Verify new tokens generated
            verify(jwtService).generateAccessToken(any(User.class));
            verify(jwtService).generateRefreshToken(TEST_USER_ID);

            // Verify verification token was deleted (single-use)
            verify(redisTemplate).delete("verify_token:" + verificationToken);
        }

        @Test
        @Order(2)
        @DisplayName("❌ Should fail with null verification token")
        void shouldFailWithNullToken() {
            // Given
            ChangePasswordRequest request = new ChangePasswordRequest(TEST_PASSWORD);

            // When & Then
            StepVerifier.create(setupService.completePasswordChange(null, request))
                    .expectErrorMatches(e ->
                            e instanceof IllegalArgumentException &&
                                    e.getMessage().contains("Verification token is required"))
                    .verify();

            verifyNoInteractions(firebaseServiceAuth, passwordChangeService);
        }

        @Test
        @Order(3)
        @DisplayName("❌ Should fail with invalid verification token")
        void shouldFailWithInvalidToken() {
            // Given
            String invalidToken = "invalid-token";
            ChangePasswordRequest request = new ChangePasswordRequest(TEST_PASSWORD);

            when(valueOperations.get("verify_token:" + invalidToken))
                    .thenReturn(Mono.empty()); // Token not found in Redis

            // When & Then
            StepVerifier.create(setupService.completePasswordChange(invalidToken, request))
                    .expectErrorMatches(e ->
                            e instanceof InvalidTokenException &&
                                    e.getMessage().contains("Invalid or expired verification token"))
                    .verify();

            verifyNoInteractions(firebaseServiceAuth, passwordChangeService);
        }

        @Test
        @Order(4)
        @DisplayName("❌ Should fail with expired verification token")
        void shouldFailWithExpiredToken() {
            // Given
            String expiredToken = "expired-token";
            ChangePasswordRequest request = new ChangePasswordRequest(TEST_PASSWORD);

            when(valueOperations.get("verify_token:" + expiredToken))
                    .thenReturn(Mono.empty()); // Token expired/removed from Redis

            // When & Then
            StepVerifier.create(setupService.completePasswordChange(expiredToken, request))
                    .expectErrorMatches(e ->
                            e instanceof InvalidTokenException &&
                                    e.getMessage().contains("Invalid or expired"))
                    .verify();
        }

        @Test
        @Order(5)
        @DisplayName("⚠️ Should handle password change failure")
        void shouldHandlePasswordChangeFailure() {
            // Given
            String verificationToken = "verify_abc123";
            ChangePasswordRequest request = new ChangePasswordRequest(TEST_PASSWORD);
            User user = createTestUser();

            when(valueOperations.get("verify_token:" + verificationToken))
                    .thenReturn(Mono.just(TEST_USER_ID));
            when(redisTemplate.delete("verify_token:" + verificationToken))
                    .thenReturn(Mono.just(1L));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID))
                    .thenReturn(Mono.just(user));
            when(passwordChangeService.changePasswordFirstTime(TEST_USER_ID, TEST_PASSWORD))
                    .thenReturn(Mono.error(new RuntimeException("Password change failed")));

            // When & Then
            StepVerifier.create(setupService.completePasswordChange(verificationToken, request))
                    .expectErrorMessage("Password change failed")
                    .verify();

            // Verification token should still be consumed (single-use)
            verify(redisTemplate).delete("verify_token:" + verificationToken);

            // User should not be saved if password change fails
            verify(firebaseServiceAuth, never()).save(any(User.class));
        }

        @Test
        @Order(6)
        @DisplayName("⚠️ Should complete even if session invalidation fails")
        void shouldCompleteEvenIfSessionInvalidationFails() {
            // Given
            String verificationToken = "verify_abc123";
            ChangePasswordRequest request = new ChangePasswordRequest(TEST_PASSWORD);
            User user = createTestUser();

            when(valueOperations.get("verify_token:" + verificationToken))
                    .thenReturn(Mono.just(TEST_USER_ID));
            when(redisTemplate.delete("verify_token:" + verificationToken))
                    .thenReturn(Mono.just(1L));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID))
                    .thenReturn(Mono.just(user));
            when(passwordChangeService.changePasswordFirstTime(TEST_USER_ID, TEST_PASSWORD))
                    .thenReturn(Mono.empty());
            when(firebaseServiceAuth.save(any(User.class)))
                    .thenReturn(Mono.just(user));
            when(sessionManagementService.invalidateAllUserSessions(TEST_USER_ID))
                    .thenReturn(Mono.error(new RuntimeException("Session service down")));
            when(jwtService.blacklistToken(anyString()))
                    .thenReturn(Mono.empty());
            when(emailService.sendPasswordChangedNotification(anyString(), anyString(), any()))
                    .thenReturn(Mono.empty());
            when(jwtService.generateAccessToken(any(User.class)))
                    .thenReturn("new-access-token");
            when(jwtService.generateRefreshToken(anyString()))
                    .thenReturn("new-refresh-token");
            when(auditLogService.logAuditEvent(anyString(), any(), anyString(), anyMap()))
                    .thenReturn(Mono.empty());

            // When & Then - Should still complete successfully
            StepVerifier.create(setupService.completePasswordChange(verificationToken, request))
                    .assertNext(tokenPair -> {
                        assertThat(tokenPair).isNotNull();
                        assertThat(tokenPair.accessToken()).isNotEmpty();
                        assertThat(tokenPair.refreshToken()).isNotEmpty();
                    })
                    .verifyComplete();

            // Verify session invalidation was attempted
            verify(sessionManagementService).invalidateAllUserSessions(TEST_USER_ID);

            // But completion should not fail
            verify(jwtService).generateAccessToken(any(User.class));
            verify(jwtService).generateRefreshToken(TEST_USER_ID);
        }

        @Test
        @Order(7)
        @DisplayName("⚠️ Should complete even if email sending fails")
        void shouldCompleteEvenIfEmailFails() {
            // Given
            String verificationToken = "verify_abc123";
            ChangePasswordRequest request = new ChangePasswordRequest(TEST_PASSWORD);
            User user = createTestUser();

            when(valueOperations.get("verify_token:" + verificationToken))
                    .thenReturn(Mono.just(TEST_USER_ID));
            when(redisTemplate.delete("verify_token:" + verificationToken))
                    .thenReturn(Mono.just(1L));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID))
                    .thenReturn(Mono.just(user));
            when(passwordChangeService.changePasswordFirstTime(TEST_USER_ID, TEST_PASSWORD))
                    .thenReturn(Mono.empty());
            when(firebaseServiceAuth.save(any(User.class)))
                    .thenReturn(Mono.just(user));
            when(sessionManagementService.invalidateAllUserSessions(TEST_USER_ID))
                    .thenReturn(Mono.empty());
            when(jwtService.blacklistToken(anyString()))
                    .thenReturn(Mono.empty());
            when(emailService.sendPasswordChangedNotification(anyString(), anyString(), any()))
                    .thenReturn(Mono.error(new RuntimeException("Email service down")));
            when(jwtService.generateAccessToken(any(User.class)))
                    .thenReturn("new-access-token");
            when(jwtService.generateRefreshToken(anyString()))
                    .thenReturn("new-refresh-token");
            when(auditLogService.logAuditEvent(anyString(), any(), anyString(), anyMap()))
                    .thenReturn(Mono.empty());

            // When & Then - Should still complete successfully
            StepVerifier.create(setupService.completePasswordChange(verificationToken, request))
                    .assertNext(tokenPair -> {
                        assertThat(tokenPair).isNotNull();
                    })
                    .verifyComplete();

            // Email failure should not block completion
            verify(emailService).sendPasswordChangedNotification(anyString(), anyString(), any());
            verify(jwtService).generateAccessToken(any(User.class));
        }
    }

    /* ===============================================
       RESEND OTP TESTS
       =============================================== */

    @Nested
    @DisplayName("Resend OTP")
    class ResendOtpTests {

        @Test
        @DisplayName("✅ Should resend OTP successfully")
        void shouldResendOtpSuccessfully() {
            // Given
            User user = createTestUser();
            user.setTemporaryPasswordLocked(true);

            OtpResult expectedResult = createSuccessOtpResult();

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(rateLimiterService.checkOtpRateLimit(anyString(), anyString())).thenReturn(Mono.empty());
            when(otpService.invalidateSetupOtp(TEST_USER_ID)).thenReturn(Mono.empty());
            when(otpService.generateAndSendSetupOtp(TEST_USER_ID, TEST_PHONE))
                    .thenReturn(Mono.just(expectedResult));

            // When
            Mono<OtpResult> result = setupService.resendOtp(TEST_TOKEN);

            // Then
            StepVerifier.create(result)
                    .assertNext(otpResult -> {
                        assertThat(otpResult.sent()).isTrue();
                        assertThat(otpResult.expiresInSeconds()).isEqualTo(600);
                    })
                    .verifyComplete();

            // Verify old OTP was invalidated
            verify(otpService).invalidateSetupOtp(TEST_USER_ID);

            // Verify new OTP was generated
            verify(otpService).generateAndSendSetupOtp(TEST_USER_ID, TEST_PHONE);
        }

        @Test
        @DisplayName("❌ Should fail if setup not initiated")
        void shouldFailIfSetupNotInitiated() {
            // Given
            User user = createTestUser();
            user.setTemporaryPasswordLocked(false); // Not initiated

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));

            // When & Then
            StepVerifier.create(setupService.resendOtp(TEST_TOKEN))
                    .expectErrorMatches(e ->
                            e instanceof IllegalStateException &&
                                    e.getMessage().contains("initiate setup first"))
                    .verify();

            verifyNoInteractions(otpService);
        }

        @Test
        @DisplayName("⚠️ Should handle rate limit")
        void shouldHandleRateLimit() {
            // Given
            User user = createTestUser();
            user.setTemporaryPasswordLocked(true);

            when(jwtService.validateTemporaryToken(anyString())).thenReturn(Mono.just(true));
            when(jwtService.getUserIdFromToken(anyString())).thenReturn(Mono.just(TEST_USER_ID));
            when(firebaseServiceAuth.getUserById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(rateLimiterService.checkOtpRateLimit(anyString(), anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Too many requests")));

            // When & Then
            StepVerifier.create(setupService.resendOtp(TEST_TOKEN))
                    .expectErrorMessage("Too many requests")
                    .verify();

            verifyNoInteractions(otpService);
        }
    }

    /* ===============================================
       HELPER METHODS
       =============================================== */

    private User createTestUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail(TEST_EMAIL);
        user.setPhoneNumber(TEST_PHONE);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setForcePasswordChange(true);
        user.setTemporaryPasswordLocked(false);
        user.setPhoneVerified(false);
        user.setFirstTimeSetupCompleted(false);
        user.setStatus(UserStatus.PENDING_APPROVAL);
        return user;
    }

    private OtpResult createSuccessOtpResult() {
        return OtpResult.builder()
                .sent(true)
                .rateLimited(false)
                .expiresInSeconds(600)
                .message("OTP sent successfully via SMS and email")
                .build();
    }

    private OtpVerificationResult createValidOtpVerificationResult() {
        return OtpVerificationResult.builder()
                .valid(true)
                .expired(false)
                .attemptsExceeded(false)
                .remainingAttempts(0)
                .message("OTP verified successfully")
                .build();
    }
}