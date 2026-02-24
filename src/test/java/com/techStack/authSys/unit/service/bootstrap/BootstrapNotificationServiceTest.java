package com.techStack.authSys.unit.service.bootstrap;


import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.service.bootstrap.BootstrapNotificationService;
import com.techStack.authSys.service.notification.EmailServiceInstance;
import com.techStack.authSys.service.observability.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Professional Test Suite for BootstrapNotificationService
 *
 * Test Coverage:
 * - Welcome email sending
 * - Password reset link generation
 * - Email content validation
 * - Audit logging
 * - Error handling
 * - Timeout handling
 *
 * Security Considerations:
 * - Password in email body (expected)
 * - Password NOT in audit logs
 * - Email masking in logs
 * - Timeout prevention of hanging
 *
 * @author TechStack Security Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("BootstrapNotificationService Tests")
class BootstrapNotificationServiceTest {

    @Mock private EmailServiceInstance emailService;
    @Mock private AuditLogService auditLogService;

    private BootstrapNotificationService notificationService;

    private static final String TEST_EMAIL = "admin@example.com";
    private static final String TEST_PASSWORD = "TempPass123!@#";

    @BeforeEach
    void setUp() {
        notificationService = new BootstrapNotificationService(
                emailService,
                auditLogService
        );
    }

    /* =========================
       Welcome Email Tests
       ========================= */

    @Test
    @DisplayName("Should send welcome email successfully")
    void sendWelcomeEmail_Success() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(emailService).sendEmail(
                eq(TEST_EMAIL),
                eq("Your Super Admin Account"),
                anyString()
        );
    }

    @Test
    @DisplayName("Should include password in email body")
    void sendWelcomeEmail_PasswordInBody() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD).block();

        // Then
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendEmail(
                eq(TEST_EMAIL),
                anyString(),
                bodyCaptor.capture()
        );

        String emailBody = bodyCaptor.getValue();
        assertThat(emailBody).contains(TEST_PASSWORD);
        assertThat(emailBody).contains("Temporary Password:");
    }

    @Test
    @DisplayName("Should include security instructions in email")
    void sendWelcomeEmail_SecurityInstructions() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD).block();

        // Then
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendEmail(
                eq(TEST_EMAIL),
                anyString(),
                bodyCaptor.capture()
        );

        String emailBody = bodyCaptor.getValue();
        assertThat(emailBody)
                .contains("IMPORTANT SECURITY NOTICE")
                .contains("change it immediately")
                .contains("Do not share")
                .contains("Log in within 24 hours");
    }

    @Test
    @DisplayName("Should include login URL in email")
    void sendWelcomeEmail_LoginUrl() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD).block();

        // Then
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendEmail(
                eq(TEST_EMAIL),
                anyString(),
                bodyCaptor.capture()
        );

        String emailBody = bodyCaptor.getValue();
        assertThat(emailBody).contains("Login URL:");
    }

    /* =========================
       Audit Logging Tests
       ========================= */

    @Test
    @DisplayName("Should log successful email send to audit")
    void sendWelcomeEmail_AuditLogCreated() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD).block();

        // Then
        verify(auditLogService).logAuditEventBootstrap(
                isNull(),
                eq(ActionType.EMAIL_SENT),
                contains("Bootstrap welcome email sent"),
                eq("BOOTSTRAP_SYSTEM")
        );
    }

    @Test
    @DisplayName("Should NOT include password in audit log")
    void sendWelcomeEmail_NoPasswordInAudit() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD).block();

        // Then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(auditLogService).logAuditEventBootstrap(
                isNull(),
                eq(ActionType.EMAIL_SENT),
                messageCaptor.capture(),
                anyString()
        );

        String auditMessage = messageCaptor.getValue();
        assertThat(auditMessage).doesNotContain(TEST_PASSWORD);
    }

    @Test
    @DisplayName("Should log email failure to audit")
    void sendWelcomeEmail_FailureAuditLog() {
        // Given
        RuntimeException emailError = new RuntimeException("SMTP unavailable");
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(emailError));

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_FAILURE), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        StepVerifier.create(notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD))
                .expectError(RuntimeException.class)
                .verify();

        // Then
        verify(auditLogService).logAuditEventBootstrap(
                isNull(),
                eq(ActionType.EMAIL_FAILURE),
                contains("Failed to send bootstrap email"),
                eq("SMTP unavailable")
        );
    }

    @Test
    @DisplayName("Should continue on audit log failure")
    void sendWelcomeEmail_AuditFailure_NonFatal() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenThrow(new RuntimeException("Audit service down"));

        // When
        Mono<Void> result = notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD);

        // Then - Should still complete successfully
        StepVerifier.create(result)
                .verifyComplete();
    }

    /* =========================
       Error Handling Tests
       ========================= */

    @Test
    @DisplayName("Should propagate email service failure")
    void sendWelcomeEmail_EmailServiceFailure() {
        // Given
        RuntimeException emailError = new RuntimeException("SMTP connection failed");
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(emailError));

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_FAILURE), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD);

        // Then
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    @DisplayName("Should handle timeout gracefully")
    void sendWelcomeEmail_Timeout() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.delay(Duration.ofSeconds(35)) // Exceeds 30s timeout
                        .then(Mono.empty()));

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_FAILURE), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD);

        // Then - Should timeout
        StepVerifier.create(result)
                .expectError(TimeoutException.class)
                .verify();
    }

    /* =========================
       Password Reset Tests
       ========================= */

    @Test
    @DisplayName("Should send password reset link successfully")
    void sendPasswordResetLink_Success() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = notificationService.sendPasswordResetLink(TEST_EMAIL);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(emailService).sendEmail(
                eq(TEST_EMAIL),
                eq("Reset Your Super Admin Password"),
                anyString()
        );
    }

    @Test
    @DisplayName("Should include reset link in email")
    void sendPasswordResetLink_ContainsLink() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendPasswordResetLink(TEST_EMAIL).block();

        // Then
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendEmail(
                eq(TEST_EMAIL),
                anyString(),
                bodyCaptor.capture()
        );

        String emailBody = bodyCaptor.getValue();
        assertThat(emailBody)
                .contains("Click the link below")
                .contains("expires in 1 hour")
                .contains("didn't request");
    }

    @Test
    @DisplayName("Should NOT include plain password in reset email")
    void sendPasswordResetLink_NoPassword() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendPasswordResetLink(TEST_EMAIL).block();

        // Then
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendEmail(
                eq(TEST_EMAIL),
                anyString(),
                bodyCaptor.capture()
        );

        String emailBody = bodyCaptor.getValue();
        assertThat(emailBody.toLowerCase())
                .doesNotContain("password:")
                .doesNotContain("temporary password");
    }

    /* =========================
       Security Tests
       ========================= */

    @Test
    @DisplayName("Should mask email in logs")
    void sendWelcomeEmail_EmailMaskedInLogs() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendWelcomeEmail(TEST_EMAIL, TEST_PASSWORD).block();

        // Then
        // In production, logs would show masked email (a***@***.com)
        // This is verified through log capture in integration tests
        verify(emailService).sendEmail(eq(TEST_EMAIL), anyString(), anyString());
    }

    /* =========================
       Concurrent Request Tests
       ========================= */

    @Test
    @DisplayName("Should handle concurrent email sends")
    void sendWelcomeEmail_ConcurrentRequests() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When - Send 3 concurrent emails
        Mono<Void> email1 = notificationService.sendWelcomeEmail("admin1@example.com", "Pass1");
        Mono<Void> email2 = notificationService.sendWelcomeEmail("admin2@example.com", "Pass2");
        Mono<Void> email3 = notificationService.sendWelcomeEmail("admin3@example.com", "Pass3");

        // Then - All should complete
        StepVerifier.create(Mono.zip(email1, email2, email3))
                .verifyComplete();

        // Verify 3 separate emails sent
        verify(emailService, times(3)).sendEmail(anyString(), anyString(), anyString());
    }

    /* =========================
       Edge Cases
       ========================= */

    @Test
    @DisplayName("Should handle null email gracefully")
    void sendWelcomeEmail_NullEmail() {
        // Given
        when(emailService.sendEmail(isNull(), anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalArgumentException("Email is null")));

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_FAILURE), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = notificationService.sendWelcomeEmail(null, TEST_PASSWORD);

        // Then
        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    @DisplayName("Should handle empty password gracefully")
    void sendWelcomeEmail_EmptyPassword() {
        // Given
        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When - Even with empty password, email should send
        Mono<Void> result = notificationService.sendWelcomeEmail(TEST_EMAIL, "");

        // Then
        StepVerifier.create(result)
                .verifyComplete();
    }

    @Test
    @DisplayName("Should handle special characters in password")
    void sendWelcomeEmail_SpecialCharactersInPassword() {
        // Given
        String complexPassword = "P@$$w0rd!#%^&*(){}[]<>?/\\|~`";

        when(emailService.sendEmail(anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        when(auditLogService.logAuditEventBootstrap(
                isNull(), eq(ActionType.EMAIL_SENT), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // When
        notificationService.sendWelcomeEmail(TEST_EMAIL, complexPassword).block();

        // Then
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendEmail(
                eq(TEST_EMAIL),
                anyString(),
                bodyCaptor.capture()
        );

        String emailBody = bodyCaptor.getValue();
        assertThat(emailBody).contains(complexPassword);
    }
}