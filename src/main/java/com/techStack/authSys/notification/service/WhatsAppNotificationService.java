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

import java.util.Map;

/**
 * WhatsAppNotificationService — sends WhatsApp messages via Africa's Talking.
 *
 * Uses the same AT account as SmsNotificationService.
 * WhatsApp Business API via AT requires:
 *   1. A verified WhatsApp Business number (obtained through AT console)
 *   2. Pre-approved message templates for outbound messages
 *      (Meta/WhatsApp policy — all outbound must use approved templates)
 *
 * Template naming convention used here:
 *   booking_confirmed, booking_reminder, payment_received, etc.
 *   These must be submitted to Meta for approval before going live.
 *
 * For sandbox testing: AT's sandbox allows free-form messages.
 * For production: only approved template names work.
 *
 * AT WhatsApp docs: https://developers.africastalking.com/docs/whatsapp
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WhatsAppNotificationService {

    private final NotificationConfig         config;
    private final NotificationLogRepository  logRepository;
    private final NotificationTemplateEngine templateEngine;
    private final WebClient                  webClient;

    public Mono<Void> send(NotificationType type, NotificationContext ctx,
                           NotificationLog logEntry) {

        if (ctx.getCustomerPhone() == null || ctx.getCustomerPhone().isBlank()) {
            return Mono.fromRunnable(() -> {
                logEntry.markSkipped("No phone number on record");
                logRepository.save(logEntry);
            }).subscribeOn(Schedulers.boundedElastic()).then();
        }

        String body = templateEngine.renderBody(type, NotificationChannel.WHATSAPP, ctx);
        logEntry.setBody(body);

        // AT WhatsApp API payload
        // In production: add "template" object with approved template name + components
        Map<String, Object> payload = Map.of(
            "username", config.getAfricasTalking().getUsername(),
            "to",       ctx.getCustomerPhone(),
            "message",  Map.of(
                "type", "text",
                "text", Map.of("body", body)
            ),
            "from",     config.getAfricasTalking().getWhatsappFrom()
        );

        return webClient.post()
            .uri(config.getAfricasTalking().getWhatsAppUrl())
            .header(HttpHeaders.AUTHORIZATION,
                "ApiKey " + config.getAfricasTalking().getApiKey())
            .header("Accept", "application/json")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(payload)
            .retrieve()
            .bodyToMono(Map.class)
            .flatMap(response -> Mono.fromRunnable(() -> {
                String messageId = extractMessageId(response);
                logEntry.markSent(messageId);
                logRepository.save(logEntry);
                log.info("WhatsApp sent: type={} to={} messageId={}",
                    type, ctx.getCustomerPhone(), messageId);
            }).subscribeOn(Schedulers.boundedElastic()))
            .onErrorResume(e -> Mono.fromRunnable(() -> {
                logEntry.markFailed(e.getMessage());
                logRepository.save(logEntry);
                log.error("WhatsApp failed: type={} to={} error={}",
                    type, ctx.getCustomerPhone(), e.getMessage());
            }).subscribeOn(Schedulers.boundedElastic()))
            .then();
    }

    @SuppressWarnings("unchecked")
    private String extractMessageId(Map<String, Object> response) {
        try {
            return (String) response.get("messageId");
        } catch (Exception e) {
            return null;
        }
    }
}
