package com.techStack.authSys.payment.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.models.BookingStatus;
import com.techStack.authSys.booking.repository.BookingRepository;
import com.techStack.authSys.booking.service.BookingService;
import com.techStack.authSys.common.exception.CustomException;
import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.payment.dto.request.MpesaCallbackRequest;
import com.techStack.authSys.payment.dto.request.StkPushRequest;
import com.techStack.authSys.payment.dto.response.*;
import com.techStack.authSys.payment.models.Payment;
import com.techStack.authSys.payment.models.PaymentMethod;
import com.techStack.authSys.payment.models.PaymentStatus;
import com.techStack.authSys.payment.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.UUID;

/**
 * PaymentService — orchestrator for the full M-Pesa payment lifecycle.
 *
 * Flow:
 *   1. Customer POSTs to /api/payments/mpesa/stk-push
 *      → initiateMpesaPayment(): load booking, create Payment(PENDING), call MpesaService.initiateStkPush()
 *      → return StkPushResponse with paymentId + checkoutRequestId
 *
 *   2. Frontend polls GET /api/payments/{id}/status until not PENDING
 *
 *   3. Safaricom POSTs to /api/payments/mpesa/callback (async, no auth)
 *      → handleMpesaCallback(): find Payment by checkoutRequestId
 *        a. ResultCode == 0  → payment.markSuccess() → BookingService.confirmBooking()
 *        b. ResultCode == 1032 → payment.markCancelled()
 *        c. Anything else    → payment.markFailed()
 *
 * Threading: JPA calls on boundedElastic, WebClient calls stay on event loop.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PaymentService {

    private final PaymentRepository  paymentRepository;
    private final BookingRepository  bookingRepository;
    private final BookingService     bookingService;
    private final MpesaService       mpesaService;
    private final ObjectMapper       objectMapper;

    // ── INITIATE ──────────────────────────────────────────────────────────────

    /**
     * Step 1: Initiate M-Pesa STK push for a booking.
     *
     * Guards:
     *   - Booking must exist and be PENDING_PAYMENT
     *   - No existing SUCCESS payment for this booking (prevent double-charge)
     *   - Request customerId must match booking.customerId (IDOR prevention)
     */
    @Transactional
    public Mono<StkPushResponse> initiateMpesaPayment(StkPushRequest req, String customerId) {

        return Mono.fromCallable(() -> {
            // Load and validate booking
            Booking booking = bookingRepository.findByIdAndDeletedFalse(req.bookingId())
                .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Booking not found: " + req.bookingId()));

            // IDOR — customer can only pay for their own booking
            if (!booking.getCustomerId().equals(customerId)) {
                throw new CustomException(HttpStatus.FORBIDDEN,
                    "You are not authorised to pay for this booking");
            }

            if (booking.getStatus() != BookingStatus.PENDING_PAYMENT) {
                throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Booking is not awaiting payment. Current status: "
                    + booking.getStatus().getDescription());
            }

            // Prevent double-charge
            if (paymentRepository.existsByBookingIdAndStatus(
                    booking.getId(), PaymentStatus.SUCCESS)) {
                throw new CustomException(HttpStatus.CONFLICT,
                    "A successful payment already exists for this booking");
            }

            // Create PENDING payment row before calling Daraja
            // (so we have a record even if the network call fails)
            Payment payment = Payment.builder()
                .booking(booking)
                .customerId(customerId)
                .amount(booking.getTotalPrice())
                .currency(booking.getCurrency())
                .method(PaymentMethod.MPESA)
                .status(PaymentStatus.PENDING)
                .phoneNumber(req.phoneNumber())
                .build();

            return paymentRepository.save(payment);

        })
        .subscribeOn(Schedulers.boundedElastic())
        // Chain the Daraja STK push (non-blocking WebClient stays on event loop)
        .flatMap(savedPayment ->
            mpesaService.initiateStkPush(
                req.phoneNumber(),
                savedPayment.getAmount(),
                "BK-" + savedPayment.getBooking().getId().toString().substring(0, 8).toUpperCase(),
                req.description()
            )
            .flatMap(darajaResp -> {
                String checkoutRequestId = (String) darajaResp.get("CheckoutRequestID");
                String merchantRequestId = (String) darajaResp.get("MerchantRequestID");
                String responseCode      = (String) darajaResp.get("ResponseCode");

                if (!"0".equals(responseCode)) {
                    // Daraja rejected the request synchronously
                    String errMsg = (String) darajaResp.getOrDefault(
                        "errorMessage", "STK push rejected by Safaricom");
                    log.error("STK push rejected: {}", darajaResp);

                    // Mark payment failed and save
                    return Mono.fromCallable(() -> {
                        savedPayment.markFailed(-1, errMsg, darajaResp.toString());
                        paymentRepository.save(savedPayment);
                        return savedPayment;
                    })
                    .subscribeOn(Schedulers.boundedElastic())
                    .flatMap(p -> Mono.error(new CustomException(
                        HttpStatus.BAD_GATEWAY, "Payment initiation failed: " + errMsg)));
                }

                // Update payment row with Daraja IDs
                return Mono.fromCallable(() -> {
                    savedPayment.setCheckoutRequestId(checkoutRequestId);
                    savedPayment.setMerchantRequestId(merchantRequestId);
                    paymentRepository.save(savedPayment);

                    log.info("STK push sent: paymentId={} checkoutRequestId={}",
                        savedPayment.getId(), checkoutRequestId);

                    return StkPushResponse.builder()
                        .paymentId(savedPayment.getId())
                        .checkoutRequestId(checkoutRequestId)
                        .phoneNumber(req.phoneNumber())
                        .amount(savedPayment.getAmount())
                        .status("PENDING")
                        .message("Check your phone and enter your M-Pesa PIN to complete payment.")
                        .build();
                }).subscribeOn(Schedulers.boundedElastic());
            })
        )
        .onErrorResume(CustomException.class, Mono::error)
        .onErrorResume(e -> {
            log.error("STK push error: {}", e.getMessage(), e);
            return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                "Payment initiation failed. Please try again."));
        });
    }

    // ── CALLBACK ──────────────────────────────────────────────────────────────

    /**
     * Step 3: Handle the async M-Pesa callback from Safaricom.
     *
     * This endpoint has NO authentication — Safaricom calls it directly.
     * IP whitelisting at the reverse proxy (Nginx/Render) is the security layer.
     *
     * Processing:
     *   a. ResultCode == 0   → markSuccess → confirmBooking (PENDING_PAYMENT → CONFIRMED)
     *   b. ResultCode == 1032→ markCancelled
     *   c. Any other code    → markFailed
     *
     * Always returns HTTP 200 to Safaricom — non-200 triggers retries.
     * Errors are handled internally (logged, payment marked failed) without
     * propagating to Safaricom's retry logic.
     */
    @Transactional
    public Mono<Void> handleMpesaCallback(MpesaCallbackRequest callbackRequest) {

        return Mono.fromCallable(() -> {
            MpesaCallbackRequest.StkCallback stkCallback = callbackRequest.getStkCallback();

            if (stkCallback == null) {
                log.error("Malformed M-Pesa callback — stkCallback is null");
                return null;
            }

            String checkoutRequestId = stkCallback.getCheckoutRequestId();
            log.info("M-Pesa callback received: checkoutRequestId={} resultCode={}",
                checkoutRequestId, stkCallback.getResultCode());

            // Serialize raw payload for audit
            String rawPayload;
            try {
                rawPayload = objectMapper.writeValueAsString(callbackRequest);
            } catch (Exception e) {
                rawPayload = callbackRequest.toString();
            }

            // Find the payment row by checkoutRequestId
            Payment payment = paymentRepository
                .findByCheckoutRequestId(checkoutRequestId)
                .orElse(null);

            if (payment == null) {
                log.error("No payment found for checkoutRequestId: {}", checkoutRequestId);
                return null; // Can't process — return 200 to Safaricom regardless
            }

            // Guard — only process PENDING payments
            if (payment.getStatus() != PaymentStatus.PENDING) {
                log.warn("Duplicate callback for already-processed payment: {} status={}",
                    payment.getId(), payment.getStatus());
                return null;
            }

            if (callbackRequest.isSuccess()) {
                // ── SUCCESS path ─────────────────────────────────────────────
                String receiptNumber = callbackRequest.getMetadataValue("MpesaReceiptNumber");
                payment.markSuccess(receiptNumber, rawPayload);
                paymentRepository.save(payment);

                log.info("✅ Payment success: id={} receipt={} bookingId={}",
                    payment.getId(), receiptNumber, payment.getBooking().getId());

                // Transition booking PENDING_PAYMENT → CONFIRMED
                // This is a blocking call inside fromCallable — correct pattern
                bookingRepository.findByIdAndDeletedFalse(payment.getBooking().getId())
                    .ifPresent(booking -> {
                        if (booking.getStatus() == BookingStatus.PENDING_PAYMENT) {
                            booking.confirm();
                            bookingRepository.save(booking);
                            log.info("✅ Booking confirmed: {} via payment {}",
                                booking.getId(), payment.getId());
                        }
                    });

            } else if (callbackRequest.isCancelledByUser()) {
                // ── CANCELLED path ────────────────────────────────────────────
                payment.markCancelled(rawPayload);
                paymentRepository.save(payment);
                log.info("🚫 Payment cancelled by customer: paymentId={}", payment.getId());

            } else {
                // ── FAILED path ───────────────────────────────────────────────
                payment.markFailed(
                    stkCallback.getResultCode(),
                    stkCallback.getResultDesc(),
                    rawPayload);
                paymentRepository.save(payment);
                log.warn("❌ Payment failed: paymentId={} code={} desc={}",
                    payment.getId(), stkCallback.getResultCode(), stkCallback.getResultDesc());
            }

            return null;

        })
        .subscribeOn(Schedulers.boundedElastic())
        .doOnError(e -> log.error("Error processing M-Pesa callback: {}", e.getMessage(), e))
        .onErrorResume(e -> Mono.empty()) // Always return 200 to Safaricom
        .then();
    }

    // ── STATUS POLL ───────────────────────────────────────────────────────────

    /**
     * Frontend polls this after initiating payment.
     * Returns PENDING until the callback arrives and updates the row.
     */
    public Mono<PaymentStatusResponse> getPaymentStatus(UUID paymentId, String customerId) {
        return Mono.fromCallable(() -> {
            Payment payment = paymentRepository.findById(paymentId)
                .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND,
                    "Payment not found: " + paymentId));

            // IDOR — customer can only check their own payment status
            if (!payment.getCustomerId().equals(customerId)) {
                throw new CustomException(HttpStatus.FORBIDDEN,
                    "Not authorised to view this payment");
            }

            String message = switch (payment.getStatus()) {
                case PENDING   -> "Waiting for your M-Pesa confirmation...";
                case SUCCESS   -> "Payment received! Your booking is confirmed.";
                case FAILED    -> "Payment failed. " + payment.getResultDescription();
                case CANCELLED -> "You cancelled the payment. You can try again.";
                case REFUNDED  -> "This payment has been refunded.";
            };

            return PaymentStatusResponse.builder()
                .paymentId(payment.getId())
                .status(payment.getStatus())
                .statusDescription(payment.getStatus().getDescription())
                .mpesaReceiptNumber(payment.getMpesaReceiptNumber())
                .message(message)
                .build();

        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ── READ ──────────────────────────────────────────────────────────────────

    /**
     * All payments for a booking — staff detail view.
     */
    public Flux<PaymentResponse> getPaymentsByBooking(UUID bookingId) {
        return Mono.fromCallable(() ->
            paymentRepository.findByBookingIdOrderByInitiatedAtDesc(bookingId)
                .stream().map(this::toResponse).toList()
        ).subscribeOn(Schedulers.boundedElastic())
         .flatMapMany(Flux::fromIterable);
    }

    /**
     * Payment history for the authenticated customer.
     */
    public Flux<PaymentResponse> getMyPayments(String customerId) {
        return Mono.fromCallable(() ->
            paymentRepository.findByCustomerIdOrderByInitiatedAtDesc(customerId)
                .stream().map(this::toResponse).toList()
        ).subscribeOn(Schedulers.boundedElastic())
         .flatMapMany(Flux::fromIterable);
    }

    // ── STATS ─────────────────────────────────────────────────────────────────

    /**
     * Payment status counts and total revenue — admin dashboard.
     */
    public Mono<PaymentStatsResponse> getStats() {
        return Mono.fromCallable(() -> {
            long pending    = paymentRepository.countByStatus(PaymentStatus.PENDING);
            long successful = paymentRepository.countByStatus(PaymentStatus.SUCCESS);
            long failed     = paymentRepository.countByStatus(PaymentStatus.FAILED);
            long cancelled  = paymentRepository.countByStatus(PaymentStatus.CANCELLED);
            long refunded   = paymentRepository.countByStatus(PaymentStatus.REFUNDED);

            return PaymentStatsResponse.builder()
                .pending(pending)
                .successful(successful)
                .failed(failed)
                .cancelled(cancelled)
                .refunded(refunded)
                .totalRevenue(paymentRepository.sumSuccessfulAmount())
                .totalAttempts(pending + successful + failed + cancelled + refunded)
                .build();

        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ── REFUND ────────────────────────────────────────────────────────────────

    /**
     * Mark the payment as REFUNDED — ADMIN only.
     * Called after BookingService.refundBooking() confirms the booking is CANCELLED.
     * Actual money transfer is handled externally (manual M-Pesa reversal or
     * Daraja B2C — Phase 2). This marks the record only.
     */
    @Transactional
    public Mono<PaymentResponse> processRefund(UUID bookingId) {
        return Mono.fromCallable(() -> {
            Payment payment = paymentRepository
                .findByBookingIdAndStatus(bookingId, PaymentStatus.SUCCESS)
                .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND,
                    "No successful payment found for booking: " + bookingId));

            payment.markRefunded();
            Payment saved = paymentRepository.save(payment);
            log.info("💰 Payment marked refunded: id={} bookingId={}", saved.getId(), bookingId);
            return toResponse(saved);

        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ── Mapper ────────────────────────────────────────────────────────────────

    private PaymentResponse toResponse(Payment p) {
        return PaymentResponse.builder()
            .id(p.getId())
            .bookingId(p.getBooking().getId())
            .customerId(p.getCustomerId())
            .amount(p.getAmount())
            .currency(p.getCurrency())
            .method(p.getMethod())
            .status(p.getStatus())
            .statusDescription(p.getStatus().getDescription())
            .phoneNumber(p.getPhoneNumber())
            .checkoutRequestId(p.getCheckoutRequestId())
            .merchantRequestId(p.getMerchantRequestId())
            .mpesaReceiptNumber(p.getMpesaReceiptNumber())
            .resultCode(p.getResultCode())
            .resultDescription(p.getResultDescription())
            .initiatedAt(p.getInitiatedAt())
            .completedAt(p.getCompletedAt())
            .build();
    }
}
