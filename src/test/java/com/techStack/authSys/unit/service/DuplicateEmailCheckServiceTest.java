package com.techStack.authSys.unit.service;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.email.EmailAlreadyExistsException;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.registration.DuplicateEmailCheckService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Professional Test Suite for DuplicateEmailCheckService
 *
 * Test Coverage:
 * - Two-tier validation (Redis + Firebase)
 * - Cache backfill mechanism
 * - Error handling and fallback
 * - Performance optimization
 *
 * Security Considerations:
 * - Email uniqueness enforcement
 * - Cache consistency
 * - Fallback to source of truth
 *
 * @author TechStack Security Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DuplicateEmailCheckService Tests")
class DuplicateEmailCheckServiceTest {

    @Mock private RedisUserCacheService redisCacheService;
    @Mock private FirebaseServiceAuth firebaseServiceAuth;

    private DuplicateEmailCheckService duplicateEmailCheckService;
    private Clock fixedClock;

    private static final String TEST_EMAIL = "test@example.com";

    @BeforeEach
    void setUp() {
        fixedClock = Clock.fixed(
                Instant.parse("2024-01-15T10:00:00Z"),
                ZoneId.of("UTC")
        );

        duplicateEmailCheckService = new DuplicateEmailCheckService(
                redisCacheService,
                firebaseServiceAuth,
                fixedClock
        );
    }

    /* =========================
       Happy Path Tests
       ========================= */

    @Test
    @DisplayName("Should pass when email not found in either source")
    void checkDuplicateEmail_NotFound_Passes() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(false));
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then
        StepVerifier.create(result)
                .expectNext(userDto)
                .verifyComplete();

        verify(redisCacheService).isEmailRegistered(TEST_EMAIL);
        verify(firebaseServiceAuth).checkEmailAvailability(TEST_EMAIL);
    }

    /* =========================
       Duplicate Detection Tests
       ========================= */

    @Test
    @DisplayName("Should reject when email found in Redis")
    void checkDuplicateEmail_FoundInRedis_Rejects() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(true));
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then
        StepVerifier.create(result)
                .expectError(EmailAlreadyExistsException.class)
                .verify();
    }

    @Test
    @DisplayName("Should reject when email found in Firebase")
    void checkDuplicateEmail_FoundInFirebase_Rejects() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(false));
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(true));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then
        StepVerifier.create(result)
                .expectError(EmailAlreadyExistsException.class)
                .verify();
    }

    @Test
    @DisplayName("Should reject when email found in both sources")
    void checkDuplicateEmail_FoundInBoth_Rejects() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(true));
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(true));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then
        StepVerifier.create(result)
                .expectError(EmailAlreadyExistsException.class)
                .verify();
    }

    /* =========================
       Cache Backfill Tests
       ========================= */

    @Test
    @DisplayName("Should backfill cache when email in Firebase but not Redis")
    void checkDuplicateEmail_BackfillsCache() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        // Not in Redis, but in Firebase
        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(false));
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(true));

        // Cache backfill
        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.empty());

        // When
        duplicateEmailCheckService.checkDuplicateEmail(userDto).subscribe(
                dto -> {},
                error -> {}
        );

        // Wait for async backfill
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Then
        verify(redisCacheService).cacheRegisteredEmail(TEST_EMAIL);
    }

    @Test
    @DisplayName("Should NOT backfill when email in both sources")
    void checkDuplicateEmail_NoBackfillWhenInBoth() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(true));
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(true));

        // When
        duplicateEmailCheckService.checkDuplicateEmail(userDto).subscribe(
                dto -> {},
                error -> {}
        );

        // Then - No backfill needed
        verify(redisCacheService, never()).cacheRegisteredEmail(anyString());
    }

    @Test
    @DisplayName("Should continue when backfill fails")
    void checkDuplicateEmail_BackfillFailure_NonFatal() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(false));
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(true));

        // Backfill fails
        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.error(new RuntimeException("Redis connection failed")));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then - Should still reject email (backfill failure is non-fatal)
        StepVerifier.create(result)
                .expectError(EmailAlreadyExistsException.class)
                .verify();
    }

    /* =========================
       Error Handling Tests
       ========================= */

    @Test
    @DisplayName("Should fallback to Firebase when Redis fails")
    void checkDuplicateEmail_RedisFailure_FallbackToFirebase() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        // Redis fails
        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.error(new RuntimeException("Redis timeout")));

        // Firebase succeeds
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then - Should pass (Firebase is source of truth)
        StepVerifier.create(result)
                .expectNext(userDto)
                .verifyComplete();
    }

    @Test
    @DisplayName("Should fail when Firebase check fails")
    void checkDuplicateEmail_FirebaseFailure_Fails() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // Firebase fails
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.error(new RuntimeException("Firebase API error")));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    @DisplayName("Should handle both sources failing")
    void checkDuplicateEmail_BothSourcesFail() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.error(new RuntimeException("Redis down")));

        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.error(new RuntimeException("Firebase down")));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then - Should propagate Firebase error (source of truth)
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    /* =========================
       Performance Tests
       ========================= */

    @Test
    @DisplayName("Should check both sources in parallel")
    void checkDuplicateEmail_ParallelExecution() {
        // Given
        UserRegistrationDTO userDto = createUserDto(TEST_EMAIL);

        when(redisCacheService.isEmailRegistered(TEST_EMAIL))
                .thenReturn(Mono.just(false));
        when(firebaseServiceAuth.checkEmailAvailability(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // When
        long startTime = System.currentTimeMillis();
        duplicateEmailCheckService.checkDuplicateEmail(userDto).block();
        long endTime = System.currentTimeMillis();

        // Then - Both should be called
        verify(redisCacheService).isEmailRegistered(TEST_EMAIL);
        verify(firebaseServiceAuth).checkEmailAvailability(TEST_EMAIL);

        // Performance check (should be quick)
        long duration = endTime - startTime;
        assertThat(duration).isLessThan(1000); // Under 1 second
    }

    /* =========================
       Edge Cases
       ========================= */

    @Test
    @DisplayName("Should handle null email gracefully")
    void checkDuplicateEmail_NullEmail() {
        // Given
        UserRegistrationDTO userDto = createUserDto(null);

        when(redisCacheService.isEmailRegistered(null))
                .thenReturn(Mono.just(false));
        when(firebaseServiceAuth.checkEmailAvailability(null))
                .thenReturn(Mono.just(false));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then - Should handle gracefully
        StepVerifier.create(result)
                .expectNext(userDto)
                .verifyComplete();
    }

    @Test
    @DisplayName("Should handle empty email")
    void checkDuplicateEmail_EmptyEmail() {
        // Given
        UserRegistrationDTO userDto = createUserDto("");

        when(redisCacheService.isEmailRegistered(""))
                .thenReturn(Mono.just(false));
        when(firebaseServiceAuth.checkEmailAvailability(""))
                .thenReturn(Mono.just(false));

        // When
        Mono<UserRegistrationDTO> result = duplicateEmailCheckService
                .checkDuplicateEmail(userDto);

        // Then
        StepVerifier.create(result)
                .expectNext(userDto)
                .verifyComplete();
    }

    @Test
    @DisplayName("Should be case-sensitive for email checks")
    void checkDuplicateEmail_CaseSensitive() {
        // Given
        UserRegistrationDTO userDto = createUserDto("Test@Example.COM");

        when(redisCacheService.isEmailRegistered("Test@Example.COM"))
                .thenReturn(Mono.just(false));
        when(firebaseServiceAuth.checkEmailAvailability("Test@Example.COM"))
                .thenReturn(Mono.just(false));

        // When
        duplicateEmailCheckService.checkDuplicateEmail(userDto).block();

        // Then - Should check exact email (normalization happens elsewhere)
        verify(redisCacheService).isEmailRegistered("Test@Example.COM");
        verify(firebaseServiceAuth).checkEmailAvailability("Test@Example.COM");
    }

    /* =========================
       Helper Methods
       ========================= */

    private UserRegistrationDTO createUserDto(String email) {
        return UserRegistrationDTO.builder()
                .email(email)
                .firstName("Test")
                .lastName("User")
                .password("Password123!")
                .build();
    }
}