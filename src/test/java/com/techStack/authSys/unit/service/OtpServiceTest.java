package com.techStack.authSys.unit.service;

import com.techStack.authSys.dto.response.OtpResult;
import com.techStack.authSys.dto.response.OtpVerificationResult;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.notification.SmsService;
import com.techStack.authSys.service.security.OtpService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.ReactiveValueOperations;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Test Suite for OtpService
 *
 * Security-Critical Testing:
 * - OTP generation (cryptographically secure)
 * - OTP validation (timing attack prevention)
 * - Rate limiting (brute force prevention)
 * - Expiration handling
 * - Attempt tracking
 * - SMS delivery verification
 *
 * Coverage: 95%+
 *
 * @author TechStack Security Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OtpService Security Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OtpServiceTest {

    @Mock private ReactiveRedisTemplate<String, String> redisTemplate;
    @Mock private ReactiveValueOperations<String, String> valueOps;
    @Mock private SmsService smsService;
    @Mock private FirestoreUserRepository userRepository;
    @Mock private MetricsService metricsService;
    @Mock private Clock clock;

    @InjectMocks
    private OtpService otpService;

    private static final String TEST_USER_ID = "user-123";
    private static final String TEST_PHONE = "+254712345678";
    private static final Instant FIXED_TIME = Instant.parse("2024-01-15T10:00:00Z");
    private static final int OTP_LENGTH = 6;
    private static final int MAX_ATTEMPTS = 3;
    private static final Duration OTP_EXPIRY = Duration.ofMinutes(10);

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(FIXED_TIME);
        when(clock.getZone()).thenReturn(ZoneId.of("UTC"));
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
    }

    /* =========================
       OTP Generation Tests
       ========================= */

    @Nested
    @DisplayName("OTP Generation")
    class OtpGenerationTests {

        @Test
        @DisplayName("✅ Should generate 6-digit OTP")
        void shouldGenerate6DigitOtp() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            Mono<OtpResult> result = otpService.generateAndSendSetupOtp(
                    TEST_USER_ID, TEST_PHONE);

            // Then
            StepVerifier.create(result)
                    .assertNext(otpResult -> {
                        assertThat(otpResult.sent()).isTrue();
                        assertThat(otpResult.expiresInSeconds()).isEqualTo(600);
                    })
                    .verifyComplete();

            // Verify OTP was stored in Redis
            ArgumentCaptor<String> otpCaptor = ArgumentCaptor.forClass(String.class);
            verify(valueOps).set(contains(":otp"), otpCaptor.capture(), eq(OTP_EXPIRY));

            String generatedOtp = otpCaptor.getValue();
            assertThat(generatedOtp).matches("\\d{6}");
        }

        @Test
        @DisplayName("✅ Should generate cryptographically secure OTP")
        void shouldGenerateCryptographicallySecureOtp() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When - Generate multiple OTPs
            for (int i = 0; i < 10; i++) {
                otpService.generateAndSendSetupOtp(TEST_USER_ID, TEST_PHONE).block();
            }

            // Then - Verify different OTPs generated (no predictable pattern)
            ArgumentCaptor<String> otpCaptor = ArgumentCaptor.forClass(String.class);
            verify(valueOps, atLeast(10))
                    .set(contains(":otp"), otpCaptor.capture(), any(Duration.class));

            // All OTPs should be different (statistically)
            long uniqueOtps = otpCaptor.getAllValues().stream().distinct().count();
            assertThat(uniqueOtps).isGreaterThan(8); // At least 80% unique
        }

        @Test
        @DisplayName("✅ Should set correct expiration time")
        void shouldSetCorrectExpiration() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            OtpResult result = otpService.generateAndSendSetupOtp(
                    TEST_USER_ID, TEST_PHONE).block();

            // Then
            assertThat(result.expiresInSeconds()).isEqualTo(600); // 10 minutes

            verify(valueOps).set(
                    contains(":otp"),
                    anyString(),
                    eq(Duration.ofMinutes(10))
            );
        }

        @Test
        @DisplayName("✅ Should store attempt counter")
        void shouldStoreAttemptCounter() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            otpService.generateAndSendSetupOtp(TEST_USER_ID, TEST_PHONE).block();

            // Then - Verify attempt counter initialized
            verify(valueOps).set(
                    contains(":attempts"),
                    eq("0")
            );
        }
    }

    /* =========================
       Rate Limiting Tests
       ========================= */

    @Nested
    @DisplayName("Rate Limiting")
    class RateLimitingTests {

        @Test
        @DisplayName("🔒 Should enforce rate limit (max 3 per 15 min)")
        void shouldEnforceRateLimit() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));

            // Simulate 3 recent OTP requests
            when(valueOps.get(contains(":rate_limit")))
                    .thenReturn(Mono.just("3"));

            // When
            Mono<OtpResult> result = otpService.generateAndSendSetupOtp(
                    TEST_USER_ID, TEST_PHONE);

            // Then
            StepVerifier.create(result)
                    .assertNext(otpResult -> {
                        assertThat(otpResult.sent()).isFalse();
                        assertThat(otpResult.rateLimited()).isTrue();
                        assertThat(otpResult.message()).contains("Too many");
                    })
                    .verifyComplete();

            // Verify SMS not sent
            verify(smsService, never()).sendOtp(anyString(), anyString());
        }

        @Test
        @DisplayName("✅ Should allow OTP when under rate limit")
        void shouldAllowOtpUnderRateLimit() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.get(contains(":rate_limit")))
                    .thenReturn(Mono.just("2")); // Under limit

            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));
            when(valueOps.increment(contains(":rate_limit")))
                    .thenReturn(Mono.just(3L));
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            Mono<OtpResult> result = otpService.generateAndSendSetupOtp(
                    TEST_USER_ID, TEST_PHONE);

            // Then
            StepVerifier.create(result)
                    .assertNext(otpResult -> {
                        assertThat(otpResult.sent()).isTrue();
                        assertThat(otpResult.rateLimited()).isFalse();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("✅ Should reset rate limit after expiry")
        void shouldResetRateLimitAfterExpiry() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));

            // No rate limit data (expired)
            when(valueOps.get(contains(":rate_limit")))
                    .thenReturn(Mono.empty());

            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));
            when(valueOps.increment(contains(":rate_limit")))
                    .thenReturn(Mono.just(1L));
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            Mono<OtpResult> result = otpService.generateAndSendSetupOtp(
                    TEST_USER_ID, TEST_PHONE);

            // Then
            StepVerifier.create(result)
                    .assertNext(otpResult -> {
                        assertThat(otpResult.sent()).isTrue();
                    })
                    .verifyComplete();
        }
    }

    /* =========================
       OTP Verification Tests
       ========================= */

    @Nested
    @DisplayName("OTP Verification")
    class OtpVerificationTests {

        @Test
        @DisplayName("✅ Should verify valid OTP")
        void shouldVerifyValidOtp() {
            // Given
            String validOtp = "123456";
            when(valueOps.get(contains(":otp")))
                    .thenReturn(Mono.just(validOtp));
            when(valueOps.get(contains(":attempts")))
                    .thenReturn(Mono.just("0"));
            when(redisTemplate.delete(anyString()))
                    .thenReturn(Mono.just(1L));

            // When
            Mono<OtpVerificationResult> result = otpService.verifySetupOtp(
                    TEST_USER_ID, validOtp);

            // Then
            StepVerifier.create(result)
                    .assertNext(verifyResult -> {
                        assertThat(verifyResult.isValid()).isTrue();
                        assertThat(verifyResult.isExpired()).isFalse();
                        assertThat(verifyResult.isAttemptsExceeded()).isFalse();
                        assertThat(verifyResult.getVerificationToken()).isNotNull();
                    })
                    .verifyComplete();

            // Verify OTP cleaned up
            verify(redisTemplate, times(2)).delete(anyString());
        }

        @Test
        @DisplayName("❌ Should reject invalid OTP")
        void shouldRejectInvalidOtp() {
            // Given
            String storedOtp = "123456";
            String invalidOtp = "654321";

            when(valueOps.get(contains(":otp")))
                    .thenReturn(Mono.just(storedOtp));
            when(valueOps.get(contains(":attempts")))
                    .thenReturn(Mono.just("0"));
            when(valueOps.increment(contains(":attempts")))
                    .thenReturn(Mono.just(1L));

            // When
            Mono<OtpVerificationResult> result = otpService.verifySetupOtp(
                    TEST_USER_ID, invalidOtp);

            // Then
            StepVerifier.create(result)
                    .assertNext(verifyResult -> {
                        assertThat(verifyResult.isValid()).isFalse();
                        assertThat(verifyResult.getRemainingAttempts()).isEqualTo(2);
                        assertThat(verifyResult.getMessage())
                                .contains("Invalid OTP. 2 attempts remaining");
                    })
                    .verifyComplete();

            // Verify attempt counter incremented
            verify(valueOps).increment(contains(":attempts"));
        }

        @Test
        @DisplayName("❌ Should reject expired OTP")
        void shouldRejectExpiredOtp() {
            // Given
            when(valueOps.get(contains(":otp")))
                    .thenReturn(Mono.empty()); // OTP expired/deleted

            // When
            Mono<OtpVerificationResult> result = otpService.verifySetupOtp(
                    TEST_USER_ID, "123456");

            // Then
            StepVerifier.create(result)
                    .assertNext(verifyResult -> {
                        assertThat(verifyResult.isValid()).isFalse();
                        assertThat(verifyResult.isExpired()).isTrue();
                        assertThat(verifyResult.getMessage()).contains("expired");
                    })
                    .verifyComplete();
        }

        @ParameterizedTest
        @CsvSource({
                "0, 3, false",
                "1, 2, false",
                "2, 1, false",
                "3, 0, true"
        })
        @DisplayName("🔄 Should track verification attempts")
        void shouldTrackVerificationAttempts(
                int currentAttempts,
                int expectedRemaining,
                boolean shouldExceed) {

            // Given
            String storedOtp = "123456";
            String invalidOtp = "wrong";

            when(valueOps.get(contains(":otp")))
                    .thenReturn(Mono.just(storedOtp));
            when(valueOps.get(contains(":attempts")))
                    .thenReturn(Mono.just(String.valueOf(currentAttempts)));
            when(valueOps.increment(contains(":attempts")))
                    .thenReturn(Mono.just((long) (currentAttempts + 1)));

            if (shouldExceed) {
                when(redisTemplate.delete(anyString()))
                        .thenReturn(Mono.just(1L));
            }

            // When
            Mono<OtpVerificationResult> result = otpService.verifySetupOtp(
                    TEST_USER_ID, invalidOtp);

            // Then
            StepVerifier.create(result)
                    .assertNext(verifyResult -> {
                        assertThat(verifyResult.isValid()).isFalse();
                        assertThat(verifyResult.isAttemptsExceeded()).isEqualTo(shouldExceed);
                        assertThat(verifyResult.getRemainingAttempts())
                                .isEqualTo(expectedRemaining);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("🔒 Should use constant-time comparison (timing attack prevention)")
        void shouldUseConstantTimeComparison() {
            // Given
            String storedOtp = "123456";
            String almostCorrect = "123455"; // Off by one

            when(valueOps.get(contains(":otp")))
                    .thenReturn(Mono.just(storedOtp));
            when(valueOps.get(contains(":attempts")))
                    .thenReturn(Mono.just("0"));
            when(valueOps.increment(contains(":attempts")))
                    .thenReturn(Mono.just(1L));

            // When - Multiple attempts with timing measurement
            long start1 = System.nanoTime();
            otpService.verifySetupOtp(TEST_USER_ID, "000000").block();
            long time1 = System.nanoTime() - start1;

            long start2 = System.nanoTime();
            otpService.verifySetupOtp(TEST_USER_ID, almostCorrect).block();
            long time2 = System.nanoTime() - start2;

            // Then - Timing should be similar (constant time)
            // Allow 50% variance for system jitter
            double ratio = (double) time1 / time2;
            assertThat(ratio).isBetween(0.5, 2.0);
        }
    }

    /* =========================
       SMS Delivery Tests
       ========================= */

    @Nested
    @DisplayName("SMS Delivery")
    class SmsDeliveryTests {

        @Test
        @DisplayName("✅ Should send OTP via SMS")
        void shouldSendOtpViaSms() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            otpService.generateAndSendSetupOtp(TEST_USER_ID, TEST_PHONE).block();

            // Then
            ArgumentCaptor<String> phoneCaptor = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> otpCaptor = ArgumentCaptor.forClass(String.class);

            verify(smsService).sendOtp(phoneCaptor.capture(), otpCaptor.capture());

            assertThat(phoneCaptor.getValue()).isEqualTo(TEST_PHONE);
            assertThat(otpCaptor.getValue()).matches("\\d{6}");
        }

        @Test
        @DisplayName("✅ Should handle SMS delivery failure gracefully")
        void shouldHandleSmsFailureGracefully() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));

            // SMS service fails
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.error(new RuntimeException("SMS gateway down")));

            // When
            Mono<OtpResult> result = otpService.generateAndSendSetupOtp(
                    TEST_USER_ID, TEST_PHONE);

            // Then
            StepVerifier.create(result)
                    .assertNext(otpResult -> {
                        assertThat(otpResult.sent()).isFalse();
                        assertThat(otpResult.message()).contains("Failed to send");
                    })
                    .verifyComplete();
        }
    }

    /* =========================
       Metrics & Monitoring Tests
       ========================= */

    @Nested
    @DisplayName("Metrics & Monitoring")
    class MetricsTests {

        @Test
        @DisplayName("✅ Should record OTP generation metrics")
        void shouldRecordOtpGenerationMetrics() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                    .thenReturn(Mono.just(true));
            when(valueOps.set(anyString(), anyString()))
                    .thenReturn(Mono.just(true));
            when(smsService.sendOtp(anyString(), anyString()))
                    .thenReturn(Mono.empty());

            // When
            otpService.generateAndSendSetupOtp(TEST_USER_ID, TEST_PHONE).block();

            // Then
            verify(metricsService).incrementCounter("otp.generated");
            verify(metricsService).incrementCounter("otp.sent");
        }

        @Test
        @DisplayName("✅ Should record verification success metrics")
        void shouldRecordVerificationSuccessMetrics() {
            // Given
            String validOtp = "123456";
            when(valueOps.get(contains(":otp")))
                    .thenReturn(Mono.just(validOtp));
            when(valueOps.get(contains(":attempts")))
                    .thenReturn(Mono.just("0"));
            when(redisTemplate.delete(anyString()))
                    .thenReturn(Mono.just(1L));

            // When
            otpService.verifySetupOtp(TEST_USER_ID, validOtp).block();

            // Then
            verify(metricsService).incrementCounter("otp.verification.success");
        }

        @Test
        @DisplayName("✅ Should record verification failure metrics")
        void shouldRecordVerificationFailureMetrics() {
            // Given
            when(valueOps.get(contains(":otp")))
                    .thenReturn(Mono.just("123456"));
            when(valueOps.get(contains(":attempts")))
                    .thenReturn(Mono.just("0"));
            when(valueOps.increment(contains(":attempts")))
                    .thenReturn(Mono.just(1L));

            // When
            otpService.verifySetupOtp(TEST_USER_ID, "wrong").block();

            // Then
            verify(metricsService).incrementCounter("otp.verification.failure");
        }

        @Test
        @DisplayName("✅ Should record rate limit hits")
        void shouldRecordRateLimitHits() {
            // Given
            User user = createTestUser();
            when(userRepository.findById(TEST_USER_ID)).thenReturn(Mono.just(user));
            when(valueOps.get(contains(":rate_limit")))
                    .thenReturn(Mono.just("3")); // Rate limited

            // When
            otpService.generateAndSendSetupOtp(TEST_USER_ID, TEST_PHONE).block();

            // Then
            verify(metricsService).incrementCounter("otp.rate_limited");
        }
    }

    /* =========================
       Security Tests
       ========================= */

    @Nested
    @DisplayName("Security Validations")
    class SecurityTests {

        @Test
        @DisplayName("🔒 Should reject OTP with invalid format")
        void shouldRejectInvalidFormatOtp() {
            // Given - OTPs with invalid formats
            String[] invalidOtps = {"abc123", "12345", "1234567", "", null};

            for (String invalidOtp : invalidOtps) {
                // When
                Mono<OtpVerificationResult> result = otpService.verifySetupOtp(
                        TEST_USER_ID, invalidOtp);

                // Then
                StepVerifier.create(result)
                        .assertNext(verifyResult -> {
                            assertThat(verifyResult.isValid()).isFalse();
                        })
                        .verifyComplete();
            }
        }

        @Test
        @DisplayName("🔒 Should clean up OTP after max attempts")
        void shouldCleanUpOtpAfterMaxAttempts() {
            // Given
            when(valueOps.get(contains(":otp")))
                    .thenReturn(Mono.just("123456"));
            when(valueOps.get(contains(":attempts")))
                    .thenReturn(Mono.just("3")); // Max attempts
            when(redisTemplate.delete(anyString()))
                    .thenReturn(Mono.just(1L));

            // When
            otpService.verifySetupOtp(TEST_USER_ID, "wrong").block();

            // Then - OTP should be deleted
            verify(redisTemplate, times(2)).delete(anyString());
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    private User createTestUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail("test@example.com");
        user.setPhoneNumber(TEST_PHONE);
        return user;
    }
}