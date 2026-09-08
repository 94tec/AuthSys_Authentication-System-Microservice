package com.techStack.authSys.notification.service;

import com.techStack.authSys.notification.config.NotificationConfig;
import com.techStack.authSys.notification.models.NotificationChannel;
import com.techStack.authSys.notification.models.NotificationContext;
import com.techStack.authSys.notification.models.NotificationLog;
import com.techStack.authSys.notification.models.NotificationType;
import com.techStack.authSys.notification.repository.NotificationLogRepository;
import com.techStack.authSys.notification.template.NotificationTemplateEngine;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.Map;

/**
 * EmailNotificationService — sends transactional email via Brevo.
 *
 * Extends the existing BrevoEmailService pattern used in the auth module.
 * This service handles notification-specific emails (booking, payment, account)
 * with templated content, while BrevoEmailService continues to handle
 * auth emails (OTP, password reset) directly.
 *
 * Brevo API: POST https://api.brevo.com/v3/smtp/email
 * Docs: https://developers.brevo.com/reference/sendtransacemail
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailNotificationService {

    private final NotificationConfig         config;
    private final NotificationLogRepository  logRepository;
    private final NotificationTemplateEngine templateEngine;
    private final WebClient                  webClient;

    /**
     * Send an email notification and persist the log entry.
     *
     * @param type    notification type — determines template and subject
     * @param ctx     context data for template substitution
     * @param logEntry pre-saved PENDING log row (updated in-place)
     */
    public Mono<Void> send(NotificationType type, NotificationContext ctx,
                           NotificationLog logEntry) {

        if (ctx.getCustomerEmail() == null || ctx.getCustomerEmail().isBlank()) {
            return Mono.fromRunnable(() -> {
                logEntry.markSkipped("No email address on record");
                logRepository.save(logEntry);
                log.warn("Email skipped — no address: customerId={}", ctx.getCustomerId());
            }).subscribeOn(Schedulers.boundedElastic()).then();
        }

        String subject = templateEngine.renderSubject(type, ctx);
        String htmlBody = templateEngine.renderBody(type, NotificationChannel.EMAIL, ctx);

        // Persist subject + body for audit before sending
        logEntry.setSubject(subject);
        logEntry.setBody(htmlBody);

        Map<String, Object> payload = Map.of(
            "sender",   Map.of(
                "email", config.getBrevo().getSenderEmail(),
                "name",  config.getBrevo().getSenderName()
            ),
            "to",       List.of(Map.of(
                "email", ctx.getCustomerEmail(),
                "name",  ctx.getCustomerName()
            )),
            "subject",  subject,
            "htmlContent", htmlBody
        );

        return webClient.post()
            .uri(config.getBrevo().getApiUrl())
            .header(HttpHeaders.AUTHORIZATION, "api-key " + config.getBrevo().getApiKey())
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(payload)
            .retrieve()
            .bodyToMono(Map.class)
            .flatMap(response -> Mono.fromRunnable(() -> {
                // Brevo returns { "messageId": "<...@smtp-relay.mailin.fr>" }
                String messageId = (String) response.get("messageId");
                logEntry.markSent(messageId);
                logRepository.save(logEntry);
                log.info("Email sent: type={} to={} messageId={}",
                    type, ctx.getCustomerEmail(), messageId);
            }).subscribeOn(Schedulers.boundedElastic()))
            .onErrorResume(e -> Mono.fromRunnable(() -> {
                logEntry.markFailed(e.getMessage());
                logRepository.save(logEntry);
                log.error("Email failed: type={} to={} error={}",
                    type, ctx.getCustomerEmail(), e.getMessage());
            }).subscribeOn(Schedulers.boundedElastic()))
            .then();
    }
}
