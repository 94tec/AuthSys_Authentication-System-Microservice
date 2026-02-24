package com.techStack.authSys.unit.service.notification;

import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.Firestore;
import com.techStack.authSys.config.core.AppConfig;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.notification.EmailService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.EncryptionService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.service.verification.EmailVerificationOrchestrator;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Test Suite for EmailVerificationOrchestrator
 *
 * Tests:
 * - Token generation and storage
 * - Email sending with graceful failures
 * - Parallel execution (email + storage)
 * - Link building
 * - Error handling and audit logging
 *
 * Coverage: 95%+
 *
 * @author TechStack Testing Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EmailVerificationOrchestrator Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EmailVerificationOrchestratorTest {

    @Mock private JwtService jwtService;
    @Mock private EmailService emailService;
    @Mock private EncryptionService encryptionService;
    @Mock private AuditLogService auditLogService;
    @Mock private Firestore firestore;
    @Mock private AppConfig appConfig;
    @Mock private Clock clock;

    @InjectMocks
    private EmailVerificationOrchestrator orchestrator;

    private static final Instant FIXED_TIME = Instant.parse("2024-01-15T10:00:00Z");
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_USER_ID = "user-123";
    private static final String TEST_IP = "192.168.1.1";
    private static final String TEST_TOKEN = "verification-token-123";
    private static final String TEST_HASHED_TOKEN = "hashed-token-abc";
    private static final String BASE_URL = "https://example.com";

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(FIXED_TIME);
        when(clock.getZone()).thenReturn(ZoneId.of("UTC"));
        when(appConfig.getBaseUrl()).thenReturn(BASE_URL);
    }

    /* =========================
       Success Flow Tests
       ========================= */

    @Nested
    @DisplayName("Successful Verification Email Flow")
    class SuccessFlowTests {

        @Test
        @DisplayName("✅ Should send verification email successfully")
        void shouldSendVerificationEmailSuccessfully() {
            // Given
            User user = createTestUser();
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(TEST_USER_ID, TEST_EMAIL, TEST_IP))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(TEST_TOKEN))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(TEST_USER_ID))
                    .thenReturn(docRef);
            when(docRef.update(anyMap()))
                    .thenReturn(mock());

            // When
            Mono<User> result = orchestrator.sendVerificationEmailSafely(user, TEST_IP);

            // Then
            StepVerifier.create(result)
                    .assertNext(returnedUser -> {
                        assertThat(returnedUser).isEqualTo(user);
                    })
                    .verifyComplete();

            verify(jwtService).generateEmailVerificationToken(TEST_USER_ID, TEST_EMAIL, TEST_IP);
            verify(encryptionService).hashToken(TEST_TOKEN);
            verify(emailService).sendVerificationEmail(eq(TEST_EMAIL), contains(TEST_TOKEN));
        }

        @Test
        @DisplayName("✅ Should generate correct verification link")
        void shouldGenerateCorrectVerificationLink() {
            // Given
            User user = createTestUser();
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(anyString()))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(anyString()))
                    .thenReturn(docRef);
            when(docRef.update(anyMap())).thenReturn(mock());

            // When
            orchestrator.sendVerificationEmailSafely(user, TEST_IP).block();

            // Then
            ArgumentCaptor<String> linkCaptor = ArgumentCaptor.forClass(String.class);
            verify(emailService).sendVerificationEmail(eq(TEST_EMAIL), linkCaptor.capture());

            String capturedLink = linkCaptor.getValue();
            assertThat(capturedLink).startsWith(BASE_URL);
            assertThat(capturedLink).contains("/api/v1/auth/verify-email");
            assertThat(capturedLink).contains("token=" + TEST_TOKEN);
        }

        @Test
        @DisplayName("✅ Should store hashed token in Firestore")
        void shouldStoreHashedTokenInFirestore() {
            // Given
            User user = createTestUser();
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(TEST_TOKEN))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(TEST_USER_ID))
                    .thenReturn(docRef);
            when(docRef.update(anyMap()))
                    .thenReturn(mock());

            // When
            orchestrator.sendVerificationEmailSafely(user, TEST_IP).block();

            // Then
            ArgumentCaptor<Map<String, Object>> dataCaptor = ArgumentCaptor.forClass(Map.class);
            verify(docRef).update(dataCaptor.capture());

            Map<String, Object> data = dataCaptor.getValue();
            assertThat(data).containsEntry("verificationTokenHash", TEST_HASHED_TOKEN);
            assertThat(data).containsKey("tokenExpiresAt");
            assertThat(data).containsKey("updatedAt");
        }

        @Test
        @DisplayName("✅ Should set correct token expiration (24 hours)")
        void shouldSetCorrectTokenExpiration() {
            // Given
            User user = createTestUser();
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(anyString()))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(anyString()))
                    .thenReturn(docRef);
            when(docRef.update(anyMap())).thenReturn(mock());

            // When
            orchestrator.sendVerificationEmailSafely(user, TEST_IP).block();

            // Then
            ArgumentCaptor<Map<String, Object>> dataCaptor = ArgumentCaptor.forClass(Map.class);
            verify(docRef).update(dataCaptor.capture());

            Map<String, Object> data = dataCaptor.getValue();
            Instant expiresAt = (Instant) data.get("tokenExpiresAt");
            
            Duration expiryDuration = Duration.between(FIXED_TIME, expiresAt);
            assertThat(expiryDuration).isEqualTo(Duration.ofHours(24));
        }
    }

    /* =========================
       Graceful Error Handling Tests
       ========================= */

    @Nested
    @DisplayName("Graceful Error Handling")
    class GracefulErrorHandlingTests {

        @Test
        @DisplayName("✅ Should continue registration if email fails")
        void shouldContinueRegistrationIfEmailFails() {
            // Given
            User user = createTestUser();

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(anyString()))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.error(new RuntimeException("SMTP server down")));

            // When
            Mono<User> result = orchestrator.sendVerificationEmailSafely(user, TEST_IP);

            // Then - Should return user without failing
            StepVerifier.create(result)
                    .assertNext(returnedUser -> {
                        assertThat(returnedUser).isEqualTo(user);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("✅ Should log audit event on email failure")
        void shouldLogAuditEventOnEmailFailure() {
            // Given
            User user = createTestUser();

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(anyString()))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Email service unavailable")));

            // When
            orchestrator.sendVerificationEmailSafely(user, TEST_IP).block();

            // Then
            verify(auditLogService).logAudit(
                    eq(user),
                    eq(ActionType.EMAIL_FAILURE),
                    contains("Verification email failed"),
                    eq(TEST_IP)
            );
        }

        @Test
        @DisplayName("✅ Should handle token generation failure")
        void shouldHandleTokenGenerationFailure() {
            // Given
            User user = createTestUser();

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Token generation failed")));

            // When
            Mono<User> result = orchestrator.sendVerificationEmailSafely(user, TEST_IP);

            // Then - Should gracefully handle error
            StepVerifier.create(result)
                    .assertNext(returnedUser -> {
                        assertThat(returnedUser).isEqualTo(user);
                    })
                    .verifyComplete();

            verify(auditLogService).logAudit(
                    any(User.class),
                    eq(ActionType.EMAIL_FAILURE),
                    anyString(),
                    eq(TEST_IP)
            );
        }

        @Test
        @DisplayName("✅ Should handle Firestore storage failure")
        void shouldHandleFirestoreStorageFailure() {
            // Given
            User user = createTestUser();
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(anyString()))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(anyString()))
                    .thenReturn(docRef);
            when(docRef.update(anyMap()))
                    .thenThrow(new RuntimeException("Firestore unavailable"));

            // When
            Mono<User> result = orchestrator.sendVerificationEmailSafely(user, TEST_IP);

            // Then - Should gracefully handle error
            StepVerifier.create(result)
                    .assertNext(returnedUser -> {
                        assertThat(returnedUser).isEqualTo(user);
                    })
                    .verifyComplete();
        }
    }

    /* =========================
       Parallel Execution Tests
       ========================= */

    @Nested
    @DisplayName("Parallel Execution")
    class ParallelExecutionTests {

        @Test
        @DisplayName("⚡ Should execute email send and token storage in parallel")
        void shouldExecuteInParallel() {
            // Given
            User user = createTestUser();
            DocumentReference docRef = mock(DocumentReference.class);

            // Simulate delays
            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(anyString()))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty().delayElement(Duration.ofMillis(100)));
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(anyString()))
                    .thenReturn(docRef);
            when(docRef.update(anyMap()))
                    .thenReturn(CompletableFuture.supplyAsync(() -> {
                        try {
                            Thread.sleep(100);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        return mock();
                    }));

            // When
            long start = System.currentTimeMillis();
            orchestrator.sendVerificationEmailSafely(user, TEST_IP).block();
            long duration = System.currentTimeMillis() - start;

            // Then - Should complete in ~100ms (parallel), not 200ms (sequential)
            assertThat(duration).isLessThan(150);
        }
    }

    /* =========================
       Security Tests
       ========================= */

    @Nested
    @DisplayName("Security Features")
    class SecurityTests {

        @Test
        @DisplayName("🔒 Should hash token before storage (never store plain text)")
        void shouldHashTokenBeforeStorage() {
            // Given
            User user = createTestUser();
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(TEST_TOKEN))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(anyString()))
                    .thenReturn(docRef);
            when(docRef.update(anyMap())).thenReturn(mock());

            // When
            orchestrator.sendVerificationEmailSafely(user, TEST_IP).block();

            // Then
            verify(encryptionService).hashToken(TEST_TOKEN);
            
            ArgumentCaptor<Map<String, Object>> dataCaptor = ArgumentCaptor.forClass(Map.class);
            verify(docRef).update(dataCaptor.capture());

            // Verify hashed token stored, not plain token
            assertThat(dataCaptor.getValue())
                    .containsEntry("verificationTokenHash", TEST_HASHED_TOKEN);
            assertThat(dataCaptor.getValue().values())
                    .doesNotContain(TEST_TOKEN);
        }

        @Test
        @DisplayName("🔒 Should include IP address in token generation")
        void shouldIncludeIpAddressInTokenGeneration() {
            // Given
            User user = createTestUser();
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(TEST_USER_ID, TEST_EMAIL, TEST_IP))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(anyString()))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(anyString()))
                    .thenReturn(docRef);
            when(docRef.update(anyMap())).thenReturn(mock());

            // When
            orchestrator.sendVerificationEmailSafely(user, TEST_IP).block();

            // Then
            verify(jwtService).generateEmailVerificationToken(
                    TEST_USER_ID,
                    TEST_EMAIL,
                    TEST_IP
            );
        }
    }

    /* =========================
       Edge Cases Tests
       ========================= */

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCasesTests {

        @Test
        @DisplayName("✅ Should handle user with special characters in email")
        void shouldHandleSpecialCharactersInEmail() {
            // Given
            User user = createTestUser();
            user.setEmail("test+tag@example.com");
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(TEST_TOKEN));
            when(encryptionService.hashToken(anyString()))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(eq("test+tag@example.com"), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(anyString()))
                    .thenReturn(docRef);
            when(docRef.update(anyMap())).thenReturn(mock());

            // When/Then
            StepVerifier.create(orchestrator.sendVerificationEmailSafely(user, TEST_IP))
                    .assertNext(returnedUser -> {
                        assertThat(returnedUser.getEmail()).isEqualTo("test+tag@example.com");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("✅ Should handle very long tokens")
        void shouldHandleVeryLongTokens() {
            // Given
            User user = createTestUser();
            String longToken = "a".repeat(500); // 500 char token
            DocumentReference docRef = mock(DocumentReference.class);

            when(jwtService.generateEmailVerificationToken(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(longToken));
            when(encryptionService.hashToken(longToken))
                    .thenReturn(TEST_HASHED_TOKEN);
            when(emailService.sendVerificationEmail(anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(firestore.collection(anyString())).thenReturn(mock());
            when(firestore.collection(anyString()).document(anyString()))
                    .thenReturn(docRef);
            when(docRef.update(anyMap())).thenReturn(mock());

            // When/Then
            StepVerifier.create(orchestrator.sendVerificationEmailSafely(user, TEST_IP))
                    .assertNext(returnedUser -> {
                        assertThat(returnedUser).isNotNull();
                    })
                    .verifyComplete();

            verify(encryptionService).hashToken(longToken);
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    private User createTestUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail(TEST_EMAIL);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setStatus(UserStatus.PENDING_APPROVAL);
        return user;
    }
}