package com.techStack.authSys.payment.controller;

import com.techStack.authSys.payment.dto.request.MpesaCallbackRequest;
import com.techStack.authSys.payment.service.PaymentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

/**
 * MpesaCallbackController — /api/payments/mpesa/callback
 *
 * Receives the async STK push result from Safaricom.
 *
 * Security:
 *   - NO authentication — Safaricom cannot send auth headers.
 *   - This URL must be whitelisted to Safaricom IPs only at the reverse proxy:
 *       Safaricom IP ranges: 196.201.214.0/24, 196.201.213.0/24
 *   - This controller must be excluded from your Spring Security auth filter.
 *     Add the path to your SecurityConfig permit list:
 *       .requestMatchers("/api/payments/mpesa/callback").permitAll()
 *
 * CRITICAL:
 *   Always return HTTP 200 regardless of processing outcome.
 *   Non-200 responses cause Safaricom to retry the callback repeatedly.
 *   All errors are handled internally in PaymentService.handleMpesaCallback().
 *
 * Kept as a separate controller (not in PaymentController) so that:
 *   1. Security configuration can target exactly "/api/payments/mpesa/callback"
 *   2. IP whitelisting at Nginx/load balancer level is clear and auditable
 *   3. The no-auth surface area is minimal and visible
 */
@Slf4j
@RestController
@RequestMapping("/api/payments/mpesa")
@RequiredArgsConstructor
@Tag(name = "M-Pesa Callback", description = "Safaricom STK push callback receiver — no auth")
public class MpesaCallbackController {

    private final PaymentService paymentService;

    /**
     * Safaricom posts the STK push result here asynchronously after the customer
     * confirms or dismisses the payment prompt on their phone.
     *
     * Processing is delegated entirely to PaymentService.handleMpesaCallback().
     * This controller ALWAYS returns 200 { "ResultCode": 0, "ResultDesc": "Accepted" }
     * to prevent Safaricom retries.
     */
    @PostMapping("/callback")
    @Operation(
        summary = "M-Pesa STK push callback — called by Safaricom, not by clients",
        description = "No authentication required. Must be IP-whitelisted to Safaricom ranges at reverse proxy."
    )
    public Mono<ResponseEntity<Map<String, Object>>> handleCallback(
            @RequestBody MpesaCallbackRequest callbackRequest) {

        // Log receipt immediately before any processing
        if (callbackRequest.getStkCallback() != null) {
            log.info("📲 M-Pesa callback received: checkoutRequestId={} resultCode={}",
                callbackRequest.getStkCallback().getCheckoutRequestId(),
                callbackRequest.getStkCallback().getResultCode());
        } else {
            log.warn("📲 M-Pesa callback received with null stkCallback body");
        }

        // Process async — don't let errors propagate to Safaricom
        //Map<String, Object> response = new HashMap<>();
        //response.put("ResultCode", 0);
        //response.put("ResultDesc", "Accepted");

        return paymentService.handleMpesaCallback(callbackRequest)
                .thenReturn(ResponseEntity.ok(MPESA_ACK))
                .onErrorResume(e -> {
                    log.error("Unhandled error in callback endpoint", e);
                    return Mono.just(ResponseEntity.ok(MPESA_ACK));
                });
    }
    private static final Map<String, Object> MPESA_ACK =
            Map.of(
                    "ResultCode", 0,
                    "ResultDesc", "Accepted"
            );
}
