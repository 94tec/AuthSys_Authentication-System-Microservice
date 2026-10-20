package com.techStack.authSys.notification.service;

import com.techStack.authSys.notification.config.NotificationConfig;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * BrevoClient — the ONLY class that talks to Brevo.
 *
 * Replaces: Gmail SMTP (JavaMailSender), the sendinblue SDK (BrevoEmailService, BrevoConfig)
 * and the hand-rolled WebClient call inside EmailNotificationService.
 *
 * POST https://api.brevo.com/v3/smtp/email
 * Auth header is "api-key: <key>"  (NOT "Authorization: api-key ...")
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BrevoClient {

    public record Recipient(String email, String name) {}

    public static class BrevoException extends RuntimeException {
        private final int status;

        public BrevoException(int status, String body) {
            super("Brevo HTTP " + status + ": " + body);
            this.status = status;
        }

        public int getStatus() { return status; }

        boolean isTransient() { return status == 429 || status >= 500; }
    }

    private final NotificationConfig config;
    private final WebClient.Builder webClientBuilder;

    private WebClient webClient;

    @PostConstruct
    void init() {
        this.webClient = webClientBuilder.clone().build();
        NotificationConfig.Brevo b = config.getBrevo();
        if (b.getApiKey() == null || b.getApiKey().isBlank()) {
            log.error("❌ notification.brevo.api-key (BREVO_API_KEY) is not set — emails will fail");
        } else {
            log.info("📧 Brevo ready: sender={} <{}> enabled={}",
                    b.getSenderName(), b.getSenderEmail(), b.isEnabled());
        }
    }

    /** Convenience: single recipient, HTML body. Emits the Brevo messageId. */
    public Mono<String> send(String toEmail, String toName, String subject, String html) {
        return send(List.of(new Recipient(toEmail, toName)), subject, html, null);
    }

    /** General send. Provide html, text, or both. Emits the Brevo messageId. */
    public Mono<String> send(List<Recipient> to, String subject, String html, String text) {
        NotificationConfig.Brevo b = config.getBrevo();

        if (to == null || to.isEmpty()) {
            return Mono.error(new IllegalArgumentException("No recipients"));
        }

        if (!b.isEnabled()) {
            log.info("📭 [Brevo DISABLED] would send '{}' to {}", subject,
                    to.stream().map(Recipient::email).toList());
            return Mono.just("disabled");
        }

        if (b.getApiKey() == null || b.getApiKey().isBlank()) {
            return Mono.error(new IllegalStateException("Brevo API key is not configured"));
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sender", Map.of("email", b.getSenderEmail(), "name", b.getSenderName()));
        payload.put("to", to.stream().map(this::toMap).toList());
        payload.put("subject", subject);
        if (html != null) payload.put("htmlContent", html);
        if (text != null) payload.put("textContent", text);

        return webClient.post()
                .uri(b.getApiUrl())
                .header("api-key", b.getApiKey())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(payload)
                .retrieve()
                .onStatus(HttpStatusCode::isError, resp ->
                        resp.bodyToMono(String.class).defaultIfEmpty("")
                                .map(body -> new BrevoException(resp.statusCode().value(), body)))
                .bodyToMono(Map.class)
                .timeout(Duration.ofSeconds(10))
                .map(r -> {
                    Object id = r.get("messageId");
                    return id == null ? "" : id.toString();
                })
                .defaultIfEmpty("")
                .retryWhen(Retry.backoff(2, Duration.ofMillis(500))
                        .maxBackoff(Duration.ofSeconds(3))
                        // retry 429/5xx and connect failures only; NOT read timeouts
                        // (the request may already have been accepted → duplicate email)
                        .filter(t -> t instanceof BrevoException be
                                ? be.isTransient()
                                : t instanceof WebClientRequestException)
                        .onRetryExhaustedThrow((spec, signal) -> signal.failure()));
    }

    private Map<String, Object> toMap(Recipient r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("email", r.email());
        if (r.name() != null && !r.name().isBlank()) m.put("name", r.name());
        return m;
    }
}