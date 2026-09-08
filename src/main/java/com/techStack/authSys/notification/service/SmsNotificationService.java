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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Map;

/**
 * SmsNotificationService — sends SMS via Africa's Talking.
 *
 * Africa's Talking (AT) is the primary choice for Kenya:
 *   - Local Kenyan DLT sender ID approval ("DAMUCHI")
 *   - KES pricing (much cheaper than Twilio for .ke numbers)
 *   - Delivery reports via webhook (AT calls your callback URL)
 *   - Sandbox environment for testing without real sends
 *
 * API: POST https://api.africastalking.com/version1/messaging
 * Auth: API key in header (ApiKey {key})
 * Body: form-encoded (not JSON — AT's legacy API shape)
 *
 * Docs: https://developers.africastalking.com/docs/sms/sending
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SmsNotificationService {

    private final NotificationConfig         config;
    private final NotificationLogRepository  logRepository;
    private final NotificationTemplateEngine templateEngine;
    private final WebClient                  webClient;

    /**
     * Send an SMS notification via Africa's Talking.
     *
     * SMS is only sent if:
     *   1. Customer has a phone number on record
     *   2. Customer has smsOptIn = true (for marketing)
     *   3. Or it's a transactional notification (marketing flag ignored)
     */
    public Mono<Void> send(NotificationType type, NotificationContext ctx,
                           NotificationLog logEntry) {

        if (ctx.getCustomerPhone() == null || ctx.getCustomerPhone().isBlank()) {
            return Mono.fromRunnable(() -> {
                logEntry.markSkipped("No phone number on record");
                logRepository.save(logEntry);
                log.debug("SMS skipped — no phone: customerId={}", ctx.getCustomerId());
            }).subscribeOn(Schedulers.boundedElastic()).then();
        }

        String body = templateEngine.renderBody(type, NotificationChannel.SMS, ctx);
        logEntry.setBody(body);

        // AT uses form-encoded body
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", config.getAfricasTalking().getUsername());
        formData.add("to",       ctx.getCustomerPhone());
        formData.add("message",  body);
        if (config.getAfricasTalking().getSenderId() != null) {
            formData.add("from", config.getAfricasTalking().getSenderId());
        }

        return webClient.post()
            .uri(config.getAfricasTalking().getSmsUrl())
            .header(HttpHeaders.AUTHORIZATION,
                "ApiKey " + config.getAfricasTalking().getApiKey())
            .header("Accept", "application/json")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData(formData))
            .retrieve()
            .bodyToMono(Map.class)
            .flatMap(response -> Mono.fromRunnable(() -> {
                // AT response: { "SMSMessageData": { "Recipients": [{ "messageId": "...", "status": "Success" }] } }
                String messageId = extractAtMessageId(response);
                logEntry.markSent(messageId);
                logRepository.save(logEntry);
                log.info("SMS sent: type={} to={} messageId={}",
                    type, ctx.getCustomerPhone(), messageId);
            }).subscribeOn(Schedulers.boundedElastic()))
            .onErrorResume(e -> Mono.fromRunnable(() -> {
                logEntry.markFailed(e.getMessage());
                logRepository.save(logEntry);
                log.error("SMS failed: type={} to={} error={}",
                    type, ctx.getCustomerPhone(), e.getMessage());
            }).subscribeOn(Schedulers.boundedElastic()))
            .then();
    }

    @SuppressWarnings("unchecked")
    private String extractAtMessageId(Map<String, Object> response) {
        try {
            Map<String, Object> smsData = (Map<String, Object>) response.get("SMSMessageData");
            if (smsData == null) return null;
            var recipients = (java.util.List<Map<String, Object>>) smsData.get("Recipients");
            if (recipients == null || recipients.isEmpty()) return null;
            return (String) recipients.get(0).get("messageId");
        } catch (Exception e) {
            log.warn("Could not extract AT message ID from response: {}", response);
            return null;
        }
    }
}
