package com.techStack.authSys.service.notification;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import sendinblue.ApiClient;
import sendinblue.auth.ApiKeyAuth;
import sibApi.TransactionalEmailsApi;
import sibModel.SendSmtpEmail;
import sibModel.SendSmtpEmailSender;
import sibModel.SendSmtpEmailTo;

import java.time.Duration;
import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    private final String apiKey;
    private final String senderEmail;
    private final String senderName;

    private final TransactionalEmailsApi emailApi;

    public EmailService(
            @Value("${brevo.api.key}") String apiKey,
            @Value("${brevo.sender.email}") String senderEmail,
            @Value("${brevo.sender.name}") String senderName, TransactionalEmailsApi emailApi
    ) {
        this.apiKey = apiKey;
        this.senderEmail = senderEmail;
        this.senderName = senderName;
        this.emailApi = emailApi;
    }

    @PostConstruct
    public void logConfiguration() {
        logger.info("Brevo API Key: {}", apiKey != null && !apiKey.isEmpty() ? "Loaded" : "NOT SET");
        logger.info("Sender Email: {}", senderEmail);
        logger.info("Sender Name: {}", senderName);

        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalStateException("Brevo API key is missing!");
        }
    }

    public Mono<Void> sendVerificationEmail(String email, String verificationLink) {
        return Mono.defer(() -> {
            try {
                String subject = "Verify Your Email Address";
                String message = "<p>Click the link below to verify your email:</p>"
                        + "<p><a href=\"" + verificationLink + "\">Verify Email</a></p>";

                sendEmail(email, subject, message);
                return Mono.empty();
            } catch (Exception e) {
                logger.error("Failed to send verification email to {}", email, e);
                return Mono.error(new RuntimeException("Failed to send verification email", e));
            }
        });
    }

    public Mono<Void> sendWelcomeEmail(String recipientEmail, String ipAddress) {
        if (recipientEmail == null || recipientEmail.isBlank()) {
            logger.warn("Invalid email: cannot send welcome email to a null or blank address");
            return Mono.error(new IllegalArgumentException("Recipient email cannot be null or blank"));
        }

        SendSmtpEmail email = new SendSmtpEmail()
                .sender(new SendSmtpEmailSender().email(senderEmail).name(senderName)) // ✅ Fix Sender
                .to(Collections.singletonList(new SendSmtpEmailTo().email(recipientEmail))) // ✅ Fix To
                .subject("Welcome to Our Service!")
                .htmlContent("<h1>Welcome!</h1><p>Thank you for joining us.</p>");

        return Mono.fromCallable(() -> emailApi.sendTransacEmail(email))
                .doOnSubscribe(subscription -> logger.info("Attempting to send welcome email to {}", recipientEmail))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(5))
                        .filter(this::isRetryableError)
                        .doBeforeRetry(retry -> logger.warn("Retrying email send: attempt #{}", retry.totalRetries() + 1)))
                .doOnSuccess(response -> logger.info("Welcome email successfully sent to {}", recipientEmail))
                .doOnError(error -> logger.error("Failed to send welcome email to {}: {}", recipientEmail, error.getMessage()))
                .onErrorResume(error -> {
                    logger.error("Email sending failed, skipping: {}", error.getMessage());
                    return Mono.empty(); // Prevents breaking app flow if email fails
                })
                .then();
    }

    private boolean isRetryableError(Throwable error) {
        return error instanceof RuntimeException; // Adjust to match retryable Brevo errors
    }

    public void sendEmail(String toEmail, String subject, String message) throws EmailSendingException {
        validateConfiguration();

        try {
            ApiClient defaultClient = initializeApiClient();
            TransactionalEmailsApi apiInstance = new TransactionalEmailsApi();
            apiInstance.setApiClient(defaultClient);

            SendSmtpEmail email = new SendSmtpEmail();
            email.setSender(new SendSmtpEmailSender().email(senderEmail).name(senderName));
            email.setTo(Collections.singletonList(new SendSmtpEmailTo().email(toEmail)));
            email.setSubject(subject);
            email.setHtmlContent(message);

            apiInstance.sendTransacEmail(email);
            logger.info("Email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            logger.error("Failed to send email to: {}", toEmail, e);
            throw new EmailSendingException("Failed to send email: " + e.getMessage());
        }
    }

    private ApiClient initializeApiClient() {
        ApiClient defaultClient = new ApiClient();
        ApiKeyAuth apiKeyAuth = (ApiKeyAuth) defaultClient.getAuthentication("api-key");

        if (apiKeyAuth == null) {
            throw new IllegalStateException("Failed to initialize Brevo API authentication. API key is null.");
        }

        apiKeyAuth.setApiKey(apiKey);
        return defaultClient;
    }

    private void validateConfiguration() {
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalStateException("Brevo API key is not configured.");
        }
        if (senderEmail == null || senderEmail.isEmpty()) {
            throw new IllegalStateException("Sender email is not configured.");
        }
        if (senderName == null || senderName.isEmpty()) {
            throw new IllegalStateException("Sender name is not configured.");
        }
    }

    public void sendSecurityNotification(String recipientEmail, String subject, String message) {
        if (recipientEmail == null || recipientEmail.isBlank()) {
            logger.warn("Invalid email: cannot send notification to a null or blank address");
            Mono.error(new IllegalArgumentException("Recipient email cannot be null or blank"));
            return;
        }

        SendSmtpEmail notificationEmail = buildEmail(recipientEmail, subject, message);

        Mono.fromCallable(() -> emailApi.sendTransacEmail(notificationEmail))
                .doOnSubscribe(subscription -> logger.info("Attempting to send security notification to {}", recipientEmail))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(5))
                        .filter(this::isRetryableError)
                        .doBeforeRetry(retry -> logger.warn("Retrying email send: attempt #{}", retry.totalRetries() + 1)))
                .doOnSuccess(response -> logger.info("Security notification successfully sent to {}", recipientEmail))
                .doOnError(error -> logger.error("Failed to send security notification to {}: {}", recipientEmail, error.getMessage()))
                .onErrorResume(error -> {
                    logger.error("Email sending failed, skipping: {}", error.getMessage());
                    return Mono.empty(); // Prevents breaking the app flow if email fails
                })
                .then();
    }

    private SendSmtpEmail buildEmail(String recipientEmail, String subject, String message) {
        return new SendSmtpEmail()
                .sender(new SendSmtpEmailSender().email(senderEmail).name(senderName))
                .to(Collections.singletonList(new SendSmtpEmailTo().email(recipientEmail)))
                .subject(subject)  // ✅ Now subject is dynamically set
                .htmlContent("<h1>Security Alert</h1><p>" + message + "</p>");  // ✅ Custom message content
    }

    public static class EmailSendingException extends Exception {
        public EmailSendingException(String message) {
            super(message);
        }
    }
}
