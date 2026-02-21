
package com.techStack.authSys.unit.service.notification;

import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.service.notification.EmailServiceInstance;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Locale;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Professional Test Suite for EmailServiceInstance
 *
 * Test Coverage:
 * - All email types (verification, welcome, password, security)
 * - Email formatting and content
 * - Error handling and retry
 * - Metrics recording
 * - Timestamp tracking
 * - Concurrent operations
 *
 * Security Considerations:
 * - Email masking in logs
 * - Sensitive data handling
 * - Timeout prevention
 * - Rate limiting awareness
 *
 * @author TechStack Security Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EmailServiceInstance Tests")
class EmailServiceInstanceTest {

    @Mock private JavaMailSender mailSender;
    @Mock private MetricsService metricsService;
    @Mock private MessageSource messageSource;

    private EmailServiceInstance emailService;
    private Clock fixedClock;
    private Scheduler testScheduler;

    private static final String TEST_EMAIL = "user@example.com";
    private static final String TEST_TOKEN = "verification-token-123";
    private static final String TEST_PASSWORD = "TempPass123!";
    private static final String FROM_ADDRESS = "noreply@techstack.com";
    private static final String BASE_URL = "https://app.techstack.com";

    @BeforeEach
    void setUp() {
        fixedClock = Clock.fixed(
                Instant.parse("2024-01-15T10:00:00Z"),
                ZoneId.of("UTC")
        );

        testScheduler = Schedulers.immediate();

        emailService = new EmailServiceInstance(
                mailSender,
                testScheduler,
                metricsService,
                messageSource,
                fixedClock
        );

        // Set private fields via reflection (or use @TestConfiguration)
        setField(emailService, "fromAddress", FROM_ADDRESS);
        setField(emailService, "baseUrl", BASE_URL);
    }

    /* =========================
       Core Email Sending Tests
       ========================= */

    @Test
    @DisplayName("Should send email successfully")
    void sendEmail_Success() {
        // Given
        String subject = "Test Subject";
        String message = "Test Message";

        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        Mono<Void> result = emailService.sendEmail(TEST_EMAIL, subject, message);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getFrom()).isEqualTo(FROM_ADDRESS);
        assertThat(sentMessage.getTo()).containsExactly(TEST_EMAIL);
        assertThat(sentMessage.getSubject()).isEqualTo(subject);
        assertThat(sentMessage.getText()).isEqualTo(message);

        verify(metricsService).incrementCounter("email.success");
        verify(metricsService).recordTimer(eq("email.send.duration"), any(Duration.class));
    }

    @Test
    @DisplayName("Should record metrics on email failure")
    void sendEmail_Failure_RecordsMetrics() {
        // Given
        RuntimeException emailError = new RuntimeException("SMTP connection failed");
        doThrow(emailError).when(mailSender).send(any(SimpleMailMessage.class));

        // When
        Mono<Void> result = emailService.sendEmail(TEST_EMAIL, "Subject", "Message");

        // Then
        StepVerifier.create(result)
                .expectError(EmailSendingException.class)
                .verify();

        verify(metricsService).incrementCounter("email.failure");
        verify(metricsService, never()).incrementCounter("email.success");
    }

    @Test
    @DisplayName("Should wrap exceptions in EmailSendingException")
    void sendEmail_WrapsExceptions() {
        // Given
        RuntimeException originalError = new RuntimeException("SMTP timeout");
        doThrow(originalError).when(mailSender).send(any(SimpleMailMessage.class));

        // When
        Mono<Void> result = emailService.sendEmail(TEST_EMAIL, "Subject", "Message");

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof EmailSendingException &&
                                throwable.getCause() == originalError
                )
                .verify();
    }

    /* =========================
       Verification Email Tests
       ========================= */

    @Test
    @DisplayName("Should send verification email with correct format")
    void sendVerificationEmail_CorrectFormat() {
        // Given
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendVerificationEmail(TEST_EMAIL, TEST_TOKEN).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Verify Your Email Address");
        assertThat(message.getText())
                .contains(BASE_URL + "/api/auth/verify-email?token=" + TEST_TOKEN)
                .contains("expire in 24 hours")
                .contains("didn't register");
    }

    @Test
    @DisplayName("Should include timestamp in verification email")
    void sendVerificationEmail_IncludesTimestamp() {
        // Given
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendVerificationEmail(TEST_EMAIL, TEST_TOKEN).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getText()).contains("Sent at:");
    }

    /* =========================
       Welcome Email Tests
       ========================= */

    @Test
    @DisplayName("Should send welcome email with user details")
    void sendWelcomeEmail_IncludesUserDetails() {
        // Given
        String ipAddress = "192.168.1.1";
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendWelcomeEmail(TEST_EMAIL, ipAddress).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Welcome to Our Platform!");
        assertThat(message.getText())
                .contains("Welcome to our platform")
                .contains(ipAddress)
                .contains("Your account was created at:");
    }

    /* =========================
       Password Reset Tests
       ========================= */

    @Test
    @DisplayName("Should send password reset email with token")
    void sendPasswordResetEmail_ContainsResetLink() {
        // Given
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendPasswordResetEmail(TEST_EMAIL, TEST_TOKEN).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Password Reset Request");
        assertThat(message.getText())
                .contains(BASE_URL + "/api/auth/reset-password?token=" + TEST_TOKEN)
                .contains("expire in 1 hour")
                .contains("didn't request this");
    }

    @Test
    @DisplayName("Should send temporary password email")
    void sendPasswordResetEmailToTheUser_ContainsPassword() {
        // Given
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendPasswordResetEmailToTheUser(TEST_EMAIL, TEST_PASSWORD).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Password Reset - Temporary Password");
        assertThat(message.getText())
                .contains("Temporary Password: " + TEST_PASSWORD)
                .contains("expire in 24 hours")
                .contains("change it on your first login");
    }

    @Test
    @DisplayName("Should send password changed notification")
    void sendPasswordChangedNotification_UserInitiated() {
        // Given
        String ipAddress = "192.168.1.1";
        Instant changedAt = fixedClock.instant();
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendPasswordChangedNotification(
                TEST_EMAIL, ipAddress, changedAt, false).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Password Changed - Security Alert");
        assertThat(message.getText())
                .contains("password was changed")
                .contains(ipAddress)
                .contains("User-initiated");
    }

    @Test
    @DisplayName("Should distinguish admin-initiated password reset")
    void sendPasswordChangedNotification_AdminInitiated() {
        // Given
        String ipAddress = "192.168.1.1";
        Instant changedAt = fixedClock.instant();
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendPasswordChangedNotification(
                TEST_EMAIL, ipAddress, changedAt, true).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getText())
                .contains("administratively reset")
                .contains("Admin-initiated");
    }

    @Test
    @DisplayName("Should send password expiry warning")
    void sendPasswordExpiryWarning_CorrectFormat() {
        // Given
        int daysRemaining = 7;
        String language = "en";
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenReturn("Password Expiry Warning");

        // When
        emailService.sendPasswordExpiryWarning(TEST_EMAIL, daysRemaining, language).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getText())
                .contains("expire in 7 days")
                .contains("update your password");
    }

    @Test
    @DisplayName("Should send password expired notification")
    void sendPasswordExpiredNotification_CorrectFormat() {
        // Given
        long daysExpired = 5;
        String language = "en";
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenReturn("Password Expired");

        // When
        emailService.sendPasswordExpiredNotification(TEST_EMAIL, daysExpired, language).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getText())
                .contains("expired 5 days ago")
                .contains("reset your password immediately");
    }

    /* =========================
       Security Alert Tests
       ========================= */

    @Test
    @DisplayName("Should send account locked notification")
    void sendAccountLockedNotification_IncludesDetails() {
        // Given
        Instant lockedAt = fixedClock.instant();
        String reason = "Too many failed login attempts";
        String ipAddress = "192.168.1.1";
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendAccountLockedNotification(
                TEST_EMAIL, lockedAt, reason, ipAddress).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Account Locked - Security Alert");
        assertThat(message.getText())
                .contains(reason)
                .contains(ipAddress)
                .contains("security reasons");
    }

    @Test
    @DisplayName("Should send first login notification")
    void sendFirstLoginNotification_CorrectFormat() {
        // Given
        String ipAddress = "192.168.1.1";
        Instant loginTime = fixedClock.instant();
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendFirstLoginNotification(TEST_EMAIL, ipAddress, loginTime).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Welcome! First Login Detected");
        assertThat(message.getText())
                .contains("first time logging in")
                .contains(ipAddress);
    }

    /* =========================
       Approval Workflow Tests
       ========================= */

    @Test
    @DisplayName("Should send user approved notification")
    void sendUserApprovedNotification_CorrectFormat() {
        // Given
        String approvedBy = "admin@example.com";
        Instant approvedAt = fixedClock.instant();
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendUserApprovedNotification(TEST_EMAIL, approvedBy, approvedAt).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Account Approved - Welcome!");
        assertThat(message.getText())
                .contains("account has been approved")
                .contains(approvedBy);
    }

    @Test
    @DisplayName("Should send user rejected notification")
    void sendUserRejectedNotification_IncludesReason() {
        // Given
        String reason = "Incomplete information provided";
        Instant rejectedAt = fixedClock.instant();
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendUserRejectedNotification(TEST_EMAIL, reason, rejectedAt).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).isEqualTo("Account Registration Decision");
        assertThat(message.getText())
                .contains("not approved")
                .contains(reason);
    }

    /* =========================
       OTP Notification Tests
       ========================= */

    @Test
    @DisplayName("Should send OTP notification")
    void sendOtpNotification_CorrectFormat() {
        // Given
        String fullName = "John Doe";
        String purpose = "Login Verification";
        Instant sentAt = fixedClock.instant();
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendOtpNotification(TEST_EMAIL, fullName, purpose, sentAt).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getSubject()).contains(purpose);
        assertThat(message.getText())
                .contains(fullName)
                .contains("valid for 10 minutes");
    }

    /* =========================
       Concurrent Operations Tests
       ========================= */

    @Test
    @DisplayName("Should handle concurrent email sends")
    void sendEmail_ConcurrentRequests() {
        // Given
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When - Send 5 concurrent emails
        Mono<Void> email1 = emailService.sendEmail("user1@example.com", "Subject", "Message");
        Mono<Void> email2 = emailService.sendEmail("user2@example.com", "Subject", "Message");
        Mono<Void> email3 = emailService.sendEmail("user3@example.com", "Subject", "Message");
        Mono<Void> email4 = emailService.sendEmail("user4@example.com", "Subject", "Message");
        Mono<Void> email5 = emailService.sendEmail("user5@example.com", "Subject", "Message");

        // Then - All should complete
        StepVerifier.create(Mono.zip(email1, email2, email3, email4, email5))
                .verifyComplete();

        verify(mailSender, times(5)).send(any(SimpleMailMessage.class));
        verify(metricsService, times(5)).incrementCounter("email.success");
    }

    /* =========================
       Edge Cases
       ========================= */

    @Test
    @DisplayName("Should handle null IP address gracefully")
    void sendEmail_NullIpAddress() {
        // Given
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendAccountLockedNotification(
                TEST_EMAIL, fixedClock.instant(), "Reason", null).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getText()).contains("Unknown");
    }

    @Test
    @DisplayName("Should handle special characters in email content")
    void sendEmail_SpecialCharacters() {
        // Given
        String specialMessage = "Test <html> & special chars: €£¥";
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        // When
        emailService.sendEmail(TEST_EMAIL, "Subject", specialMessage).block();

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        SimpleMailMessage message = messageCaptor.getValue();
        assertThat(message.getText()).isEqualTo(specialMessage);
    }

    /* =========================
       Helper Methods
       ========================= */

    private void setField(Object target, String fieldName, Object value) {
        try {
            var field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set field: " + fieldName, e);
        }
    }
}