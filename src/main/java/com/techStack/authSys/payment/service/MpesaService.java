package com.techStack.authSys.payment.service;

import com.techStack.authSys.payment.config.MpesaConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;

/**
 * MpesaService — Safaricom Daraja API integration.
 *
 * Responsibilities:
 *   1. Fetch OAuth access token (client_credentials grant)
 *   2. Build and send STK push (Lipa Na M-Pesa Online)
 *   3. Query STK push status (for timeout recovery)
 *
 * All HTTP calls use Spring WebClient (non-blocking).
 * Called by PaymentService — never called directly from controllers.
 *
 * Token caching: access tokens are valid for 1 hour.
 * Simple in-memory cache (tokenExpiresAt) avoids hammering the auth endpoint.
 * For multi-instance deployments (Phase 3) move token cache to Redis.
 *
 * Daraja docs: https://developer.safaricom.co.ke/APIs/MpesaExpressSimulate
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MpesaService {

    private final MpesaConfig mpesaConfig;
    private final WebClient   webClient;

    // ── Simple in-memory token cache ──────────────────────────────────────────
    private String    cachedToken;
    private LocalDateTime tokenExpiresAt;



    // ── OAuth token ───────────────────────────────────────────────────────────

    /**
     * Fetch a Daraja OAuth access token using client_credentials.
     * Returns cached token if still valid (> 60s remaining).
     *
     * Daraja response shape:
     * { "access_token": "xxxxx", "expires_in": "3599" }
     */
    public Mono<String> getAccessToken() {
        if (cachedToken != null && tokenExpiresAt != null
                && LocalDateTime.now().isBefore(tokenExpiresAt.minusSeconds(60))) {
            return Mono.just(cachedToken);
        }

        String credentials = mpesaConfig.getConsumerKey()
            + ":" + mpesaConfig.getConsumerSecret();
        String basicAuth = Base64.getEncoder()
            .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

        return webClient.get()
            .uri(mpesaConfig.getAuthUrl())
            .header(HttpHeaders.AUTHORIZATION, "Basic " + basicAuth)
            .retrieve()
            .bodyToMono(Map.class)
            .map(body -> {
                String token = (String) body.get("access_token");
                int expiresIn = Integer.parseInt(body.get("expires_in").toString());
                this.cachedToken    = token;
                this.tokenExpiresAt = LocalDateTime.now().plusSeconds(expiresIn);
                log.debug("M-Pesa token refreshed, expires in {}s", expiresIn);
                return token;
            })
            .doOnError(e -> log.error("Failed to fetch M-Pesa token: {}", e.getMessage()));
    }

    // ── STK Push ──────────────────────────────────────────────────────────────

    /**
     * Initiate a Lipa Na M-Pesa Online (STK Push) request.
     *
     * Sends a payment prompt to the customer's phone.
     * Customer enters their M-Pesa PIN — Safaricom calls our callback URL async.
     *
     * @param phoneNumber  e.g. "254712345678"
     * @param amount       e.g. 5000 (KES, no decimals sent to Daraja)
     * @param bookingRef   used as AccountReference and TransactionDesc
     * @return Daraja response map containing CheckoutRequestID and MerchantRequestID
     */
    public Mono<Map<String, Object>> initiateStkPush(
            String phoneNumber,
            BigDecimal amount,
            String bookingRef,
            String description) {

        return getAccessToken().flatMap(token -> {
            String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            String password  = generatePassword(timestamp);

            Map<String, Object> body = Map.ofEntries(
                    Map.entry("BusinessShortCode", mpesaConfig.getShortcode()),
                    Map.entry("Password", password),
                    Map.entry("Timestamp", timestamp),
                    Map.entry("TransactionType", mpesaConfig.getTransactionType()),
                    Map.entry("Amount", amount.toBigInteger()),
                    Map.entry("PartyA", phoneNumber),
                    Map.entry("PartyB", mpesaConfig.getShortcode()),
                    Map.entry("PhoneNumber", phoneNumber),
                    Map.entry("CallBackURL", mpesaConfig.getCallbackUrl()),
                    Map.entry("AccountReference", truncate(bookingRef, 12)),
                    Map.entry("TransactionDesc",
                            truncate(description != null ? description : "Tour Booking", 13))
            );

            log.info("STK push: phone={} amount={} ref={} env={}",
                phoneNumber, amount, bookingRef, mpesaConfig.getEnvironment());

            return webClient.post()
                .uri(mpesaConfig.getStkPushUrl())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Map.class)
                .map(resp -> (Map<String, Object>) resp)
                .doOnSuccess(resp -> log.info("STK push response: {}", resp))
                .doOnError(e -> log.error("STK push failed: {}", e.getMessage()));
        });
    }

    // ── STK Query ─────────────────────────────────────────────────────────────

    /**
     * Query the status of a pending STK push.
     * Useful for recovering from callback delivery failures or timeouts.
     * Called by PaymentService.queryAndRecoverPayment().
     *
     * @param checkoutRequestId the ID returned by initiateStkPush
     */
    public Mono<Map<String, Object>> queryStkStatus(String checkoutRequestId) {
        return getAccessToken().flatMap(token -> {
            String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));

            Map<String, Object> body = Map.of(
                "BusinessShortCode", mpesaConfig.getShortcode(),
                "Password",          generatePassword(timestamp),
                "Timestamp",         timestamp,
                "CheckoutRequestID", checkoutRequestId
            );

            log.info("STK query: checkoutRequestId={}", checkoutRequestId);

            return webClient.post()
                .uri(mpesaConfig.getStkQueryUrl())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Map.class)
                .map(resp -> (Map<String, Object>) resp)
                .doOnError(e -> log.error("STK query failed: {}", e.getMessage()));
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Daraja password = Base64(Shortcode + Passkey + Timestamp).
     * Must match exactly — Daraja rejects mismatches with error 400.
     */
    private String generatePassword(String timestamp) {
        String raw = mpesaConfig.getShortcode()
            + mpesaConfig.getPasskey()
            + timestamp;
        return Base64.getEncoder()
            .encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    /** Daraja silently truncates long strings — truncate explicitly for clarity. */
    private String truncate(String value, int maxLen) {
        if (value == null) return "";
        return value.length() <= maxLen ? value : value.substring(0, maxLen);
    }
}
