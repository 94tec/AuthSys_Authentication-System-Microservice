package com.techStack.authSys.tour.notification;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Meta WhatsApp Cloud API implementation.
 *
 * Requires, in application.yml / env vars (never hardcoded, never logged):
 *   whatsapp.api.phone-number-id   — your WABA's phone number ID
 *   whatsapp.api.access-token      — a permanent system-user access token, NOT a 24h test token
 *
 * Docs: https://developers.facebook.com/docs/whatsapp/cloud-api/reference/messages
 *
 * IMPORTANT PLATFORM CONSTRAINT: WhatsApp only allows free-form messages within
 * a 24h window after the customer last messaged you. Outside that window —
 * which covers essentially every quote-ready notification, since the customer
 * isn't mid-conversation — you MUST use a pre-approved message template.
 * templateName below must already exist and be approved in Meta Business
 * Manager before this will succeed; an unapproved/misspelled template name
 * fails the call outright with a 400 from Meta, not a silent no-op.
 */
@Slf4j
@Service
public class WhatsAppServiceInstance implements WhatsAppService {

    // E.164: + followed by 8-15 digits. Rejects anything else before it burns an API call.
    private static final Pattern E164 = Pattern.compile("^\\+[1-9]\\d{7,14}$");

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    @Value("${whatsapp.api.phone-number-id}")
    private String phoneNumberId;

    @Value("${whatsapp.api.access-token}")
    private String accessToken;

    private static final String GRAPH_API_BASE = "https://graph.facebook.com/v21.0";

    public WhatsAppServiceInstance(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
        this.webClient = webClientBuilder.baseUrl(GRAPH_API_BASE).build();
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> sendTemplatedMessage(String toPhone, String templateName, Map<String, Object> vars) {
        if (toPhone == null || !E164.matcher(toPhone).matches()) {
            log.warn("Rejected WhatsApp send — phone not in E.164 format (template={})", templateName);
            return Mono.error(new IllegalArgumentException("Phone number must be in E.164 format"));
        }
        if (accessToken == null || accessToken.isBlank()) {
            log.error("WhatsApp access token is not configured — cannot send template {}", templateName);
            return Mono.error(new IllegalStateException("WhatsApp API not configured"));
        }

        ObjectNode body = objectMapper.createObjectNode();
        body.put("messaging_product", "whatsapp");
        body.put("to", toPhone);
        body.put("type", "template");

        ObjectNode template = body.putObject("template");
        template.put("name", templateName);
        template.putObject("language").put("code", "en");

        // Template params are positional, not named — order here must exactly
        // match the {{1}}, {{2}}, ... placeholders as approved in the template.
        ArrayNode components = template.putArray("components");
        ObjectNode bodyComponent = components.addObject();
        bodyComponent.put("type", "body");
        ArrayNode parameters = bodyComponent.putArray("parameters");
        vars.values().forEach(value -> {
            ObjectNode param = parameters.addObject();
            param.put("type", "text");
            param.put("text", String.valueOf(value));
        });

        return webClient.post()
                .uri("/{phoneNumberId}/messages", phoneNumberId)
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(body)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(response -> log.info("WhatsApp template '{}' sent, status {}",
                        templateName, response.getStatusCode()))
                .then();
    }
}