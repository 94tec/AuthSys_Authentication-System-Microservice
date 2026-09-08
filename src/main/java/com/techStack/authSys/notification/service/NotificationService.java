package com.techStack.authSys.notification.service;

import com.techStack.authSys.booking.dto.response.BookingDTO;
import com.techStack.authSys.customer.models.CustomerProfile;
import com.techStack.authSys.customer.repository.CustomerProfileRepository;
import com.techStack.authSys.notification.config.NotificationConfig;
import com.techStack.authSys.notification.dto.response.NotificationLogResponse;
import com.techStack.authSys.notification.dto.response.NotificationStatsResponse;
import com.techStack.authSys.notification.models.*;
import com.techStack.authSys.notification.repository.NotificationLogRepository;
import com.techStack.authSys.payment.dto.response.PaymentResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * NotificationService — the single entry point for all notification dispatch.
 *
 * Called by:
 *   BookingService  → after confirmBooking(), cancelBooking(), completeBooking()
 *   PaymentService  → after handleMpesaCallback() SUCCESS or FAILED
 *   Auth module     → after approveUser(), rejectUser() (existing hooks)
 *   Scheduled jobs  → BOOKING_REMINDER (24h before enquire-button.tsx), retry loop
 *
 * How it works for each event:
 *   1. Build NotificationContext from the event data
 *   2. Resolve which channels to use (EMAIL always; SMS/WhatsApp if opted in)
 *   3. For each channel, create a PENDING NotificationLog row
 *   4. Dispatch to EmailNotificationService / SmsNotificationService /
 *      WhatsAppNotificationService in parallel
 *   5. Each channel service updates its log row to SENT or FAILED
 *
 * All dispatch is @Async — the calling service (BookingService, PaymentService)
 * does not wait for notification delivery. Fire-and-forget.
 *
 * Threading:
 *   - @Async on public trigger methods → off the request thread immediately
 *   - Channel services use WebClient (non-blocking) + boundedElastic for JPA
 *
 * Retry:
 *   - FAILED rows are retried by ScheduledNotificationJob every 5 minutes
 *   - Max retries configured in notification.retry.max-attempts (default 3)
 *   - Retry window: notification.retry.window-hours (default 24)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final NotificationLogRepository      logRepository;
    private final CustomerProfileRepository      customerProfileRepository;
    private final EmailNotificationService       emailService;
    private final SmsNotificationService         smsService;
    private final WhatsAppNotificationService    whatsAppService;
    private final NotificationConfig             config;

    // ── Booking lifecycle triggers ────────────────────────────────────────────

    /**
     * Called by SecurityIncidentService for HIGH/CRITICAL incidents.
     * TODO: wire to real delivery once SUPER_ADMIN contact info source is decided —
     * see options below.
     */
    public void onSecurityIncidentRaised(String type, String severity, String description, int occurrenceCount) {
        log.warn("🚨 SECURITY INCIDENT [{}/{}] occurrences={} — {}", type, severity, occurrenceCount, description);
        // TODO: replace with a real send once wired — see Option B
    }
    /**
     * Triggered after BookingService.createBooking() — booking is PENDING_PAYMENT.
     * Tells the customer we've received their booking and payment is pending.
     */
    @Async
    public void onBookingCreated(BookingDTO booking) {
        NotificationContext ctx = contextFromBooking(booking)
            .referenceId(booking.id().toString())
            .referenceType("BOOKING")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.BOOKING_CREATED, ctx);
    }

    /**
     * Triggered after BookingService.confirmBooking() — payment confirmed.
     * This is the most important notification — customer's booking receipt.
     */
    @Async
    public void onBookingConfirmed(BookingDTO booking) {
        NotificationContext ctx = contextFromBooking(booking)
            .paymentReference(booking.paymentReference())
            .referenceId(booking.id().toString())
            .referenceType("BOOKING")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.BOOKING_CONFIRMED, ctx);
    }

    /**
     * Triggered after any cancel — customer or staff.
     */
    @Async
    public void onBookingCancelled(BookingDTO booking) {
        NotificationContext ctx = contextFromBooking(booking)
            .cancellationReason(booking.cancellationReason())
            .referenceId(booking.id().toString())
            .referenceType("BOOKING")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.BOOKING_CANCELLED, ctx);
    }

    /**
     * Triggered after BookingService.completeBooking() — post-enquire-button.tsx.
     */
    @Async
    public void onBookingCompleted(BookingDTO booking) {
        NotificationContext ctx = contextFromBooking(booking)
            .referenceId(booking.id().toString())
            .referenceType("BOOKING")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.BOOKING_COMPLETED, ctx);
    }

    /**
     * Triggered by ScheduledNotificationJob 24h before tourDate.
     * Called for each confirmed booking whose enquire-button.tsx is tomorrow.
     */
    @Async
    public void onBookingReminder(BookingDTO booking) {
        NotificationContext ctx = contextFromBooking(booking)
            .referenceId(booking.id().toString())
            .referenceType("BOOKING")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.BOOKING_REMINDER, ctx);
    }

    // ── Payment triggers ──────────────────────────────────────────────────────

    /**
     * Triggered after PaymentService.handleMpesaCallback() — SUCCESS path.
     * Complements BOOKING_CONFIRMED with the M-Pesa receipt number.
     */
    @Async
    public void onPaymentReceived(PaymentResponse payment, String customerName,
                                  String customerEmail, String customerPhone) {
        CustomerProfile profile = resolveProfile(payment.getCustomerId());
        NotificationContext ctx = NotificationContext.builder()
            .customerId(payment.getCustomerId())
            .customerName(customerName)
            .customerEmail(customerEmail)
            .customerPhone(customerPhone)
            .emailOptIn(true)
            .smsOptIn(profile != null && profile.isSmsOptIn())
            .whatsAppOptIn(profile != null && profile.isSmsOptIn())
            .paymentId(payment.getId())
            .paymentAmount(payment.getAmount())
            .currency(payment.getCurrency())
            .mpesaReceiptNumber(payment.getMpesaReceiptNumber())
            .referenceId(payment.getId().toString())
            .referenceType("PAYMENT")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.PAYMENT_RECEIVED, ctx);
    }

    /**
     * Triggered after PaymentService.handleMpesaCallback() — FAILED/CANCELLED path.
     * Prompts the customer to try again.
     */
    @Async
    public void onPaymentFailed(PaymentResponse payment, String customerName,
                                String customerEmail, String customerPhone) {
        CustomerProfile profile = resolveProfile(payment.getCustomerId());
        NotificationContext ctx = NotificationContext.builder()
            .customerId(payment.getCustomerId())
            .customerName(customerName)
            .customerEmail(customerEmail)
            .customerPhone(customerPhone)
            .emailOptIn(true)
            .smsOptIn(profile != null && profile.isSmsOptIn())
            .whatsAppOptIn(profile != null && profile.isSmsOptIn())
            .paymentId(payment.getId())
            .paymentAmount(payment.getAmount())
            .paymentFailureReason(payment.getResultDescription())
            .referenceId(payment.getId().toString())
            .referenceType("PAYMENT")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.PAYMENT_FAILED, ctx);
    }

    /**
     * Triggered after BookingService.refundBooking() — ADMIN processes refund.
     */
    @Async
    public void onPaymentRefunded(BookingDTO booking) {
        NotificationContext ctx = contextFromBooking(booking)
            .referenceId(booking.id().toString())
            .referenceType("BOOKING")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.PAYMENT_REFUNDED, ctx);
    }

    // ── Account triggers ──────────────────────────────────────────────────────

    /**
     * Triggered after ADMIN approves a pending user registration.
     * Called from the existing auth approveUser() flow.
     */
    @Async
    public void onAccountApproved(String customerId, String customerName,
                                  String customerEmail) {
        NotificationContext ctx = NotificationContext.builder()
            .customerId(customerId)
            .customerName(customerName)
            .customerEmail(customerEmail)
            .emailOptIn(true) // transactional — no opt-in required
            .smsOptIn(false)
            .whatsAppOptIn(false)
            .referenceId(customerId)
            .referenceType("USER")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.ACCOUNT_APPROVED, ctx);
    }

    /**
     * Triggered after ADMIN rejects a pending user registration.
     */
    @Async
    public void onAccountRejected(String customerId, String customerName,
                                  String customerEmail, String reason) {
        NotificationContext ctx = NotificationContext.builder()
            .customerId(customerId)
            .customerName(customerName)
            .customerEmail(customerEmail)
            .emailOptIn(true)
            .smsOptIn(false)
            .whatsAppOptIn(false)
            .rejectionReason(reason)
            .referenceId(customerId)
            .referenceType("USER")
            .correlationId(UUID.randomUUID())
            .build();
        dispatch(NotificationType.ACCOUNT_REJECTED, ctx);
    }

    // ── READ: customer notification history ───────────────────────────────────

    /**
     * Customer's notification history — in-app bell feed.
     * GET /api/notifications/me
     */
    public Mono<Page<NotificationLogResponse>> getMyNotifications(
            String customerId, int page, int size) {
        return Mono.fromCallable(() -> {
            PageRequest pageable = PageRequest.of(page, size,
                Sort.by("createdDate").descending());
            return logRepository
                .findByCustomerIdOrderByCreatedDateDesc(customerId, pageable)
                .map(this::toResponse);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * All notification rows for a booking or payment — staff customer-service view.
     * GET /api/notifications/reference/{referenceId}
     */
    public Flux<NotificationLogResponse> getByReference(String referenceId) {
        return Mono.fromCallable(() ->
            logRepository.findByReferenceIdOrderByCreatedDateDesc(referenceId)
                .stream().map(this::toResponse).toList()
        ).subscribeOn(Schedulers.boundedElastic())
         .flatMapMany(Flux::fromIterable);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    /**
     * Paginated full notification log — admin monitoring dashboard.
     */
    public Mono<Page<NotificationLogResponse>> getAllNotifications(int page, int size) {
        return Mono.fromCallable(() -> {
            PageRequest pageable = PageRequest.of(page, size,
                Sort.by("createdDate").descending());
            return logRepository.findAllByOrderByCreatedDateDesc(pageable)
                .map(this::toResponse);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Delivery health stats — admin dashboard.
     */
    /**
     * Delivery health stats — admin dashboard.
     */
    public Mono<NotificationStatsResponse> getStats() {
        return Mono.fromCallable(() -> {
            Instant since24h = OffsetDateTime.now().minusHours(24).toInstant();
            return NotificationStatsResponse.builder()
                    .pending(logRepository.countByStatus(NotificationStatus.PENDING))
                    .sent(logRepository.countByStatus(NotificationStatus.SENT))
                    .delivered(logRepository.countByStatus(NotificationStatus.DELIVERED))
                    .failed(logRepository.countByStatus(NotificationStatus.FAILED))
                    .skipped(logRepository.countByStatus(NotificationStatus.SKIPPED))
                    .recentFailures(logRepository.countRecentFailures(since24h))
                    .build();
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ── Retry ─────────────────────────────────────────────────────────────────

    /**
     * Called by ScheduledNotificationJob every 5 minutes.
     * Retries FAILED and stuck PENDING notifications within the retry window.
     */
    @Transactional
    public Mono<Integer> retryFailed() {
        return Mono.fromCallable(() -> {
            int maxRetries = config.getRetry().getMaxAttempts();
            Instant cutoff = OffsetDateTime.now()
                    .minusHours(config.getRetry().getWindowHours())
                    .toInstant();
            List<NotificationLog> retryable =
                    logRepository.findRetryable(maxRetries, cutoff);
            if (retryable.isEmpty()) return 0;
            log.info("Retrying {} failed notifications", retryable.size());
            retryable.forEach(log -> {
                // Re-dispatch via the appropriate channel service
                // Channel services update the log row in-place
                Mono<Void> send = switch (log.getChannel()) {
                    case EMAIL    -> rebuildAndSendEmail(log);
                    case SMS      -> rebuildAndSendSms(log);
                    case WHATSAPP -> rebuildAndSendWhatsApp(log);
                    case IN_APP   -> Mono.empty(); // in-app never retried
                };
                send.subscribe();
            });
            return retryable.size();
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ── Core dispatch ─────────────────────────────────────────────────────────

    /**
     * Dispatch a notification to all applicable channels in parallel.
     * Creates PENDING log rows first, then fires each channel.
     */
    private void dispatch(NotificationType type, NotificationContext ctx) {
        log.info("Dispatching notification: type={} customerId={} correlationId={}",
            type, ctx.getCustomerId(), ctx.getCorrelationId());

        List<Mono<Void>> sends = new ArrayList<>();

        // EMAIL — always sent for transactional; check opt-in for marketing
        if (!type.isMarketingOnly() || ctx.isEmailOptIn()) {
            NotificationLog emailLog = createLogEntry(type, NotificationChannel.EMAIL, ctx);
            sends.add(emailService.send(type, ctx, emailLog));
        }

        // SMS — sent only if customer has phone AND smsOptIn (or transactional with phone)
        if (ctx.getCustomerPhone() != null && !ctx.getCustomerPhone().isBlank()) {
            if (!type.isMarketingOnly() || ctx.isSmsOptIn()) {
                NotificationLog smsLog = createLogEntry(type, NotificationChannel.SMS, ctx);
                sends.add(smsService.send(type, ctx, smsLog));
            }
        }

        // WHATSAPP — same gate as SMS (uses smsOptIn flag)
        if (ctx.getCustomerPhone() != null && !ctx.getCustomerPhone().isBlank()) {
            if (!type.isMarketingOnly() || ctx.isWhatsAppOptIn()) {
                NotificationLog waLog = createLogEntry(type, NotificationChannel.WHATSAPP, ctx);
                sends.add(whatsAppService.send(type, ctx, waLog));
            }
        }

        // Fire all channels in parallel — don't block on any
        if (!sends.isEmpty()) {
            Flux.merge(sends)
                .doOnError(e -> log.error(
                    "Notification dispatch error: type={} correlationId={} error={}",
                    type, ctx.getCorrelationId(), e.getMessage()))
                .subscribe();
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Create and persist a PENDING log row before sending.
     * This ensures we have an audit record even if the send call throws.
     */
    private NotificationLog createLogEntry(NotificationType type,
                                           NotificationChannel channel,
                                           NotificationContext ctx) {
        NotificationLog entry = NotificationLog.builder()
            .customerId(ctx.getCustomerId())
            .recipientEmail(ctx.getCustomerEmail())
            .recipientPhone(ctx.getCustomerPhone())
            .recipientName(ctx.getCustomerName())
            .notificationType(type)
            .channel(channel)
            .status(NotificationStatus.PENDING)
            .correlationId(ctx.getCorrelationId())
            .referenceId(ctx.getReferenceId())
            .referenceType(ctx.getReferenceType())
            .build();
        return logRepository.save(entry);
    }

    /**
     * Build a NotificationContext.Builder pre-filled from a BookingDTO.
     * Resolves customer opt-in preferences from CustomerProfile.
     */
    private NotificationContext.NotificationContextBuilder contextFromBooking(BookingDTO booking) {
        CustomerProfile profile = resolveProfile(booking.customerId());
        return NotificationContext.builder()
            .customerId(booking.customerId())
            .customerName(booking.customerName())
            .customerEmail(booking.customerEmail())
            .customerPhone(profile != null ? profile.getPhoneNumber() : null)
            .emailOptIn(true) // transactional — always send
            .smsOptIn(profile != null && profile.isSmsOptIn())
            .whatsAppOptIn(profile != null && profile.isSmsOptIn())
            .bookingId(booking.id())
            .tourName(booking.tourName())
            .tourDate(booking.tourDate())
            .travelerCount(booking.travelerCount())
            .totalPrice(booking.totalPrice())
            .currency(booking.currency());
    }

    /** Null-safe profile lookup — returns null if no profile exists yet. */
    private CustomerProfile resolveProfile(String customerId) {
        return customerProfileRepository
            .findByCustomerIdAndDeletedFalse(customerId)
            .orElse(null);
    }

    // Retry helpers — reconstruct a minimal context from the log row
    private Mono<Void> rebuildAndSendEmail(NotificationLog log) {
        NotificationContext ctx = NotificationContext.builder()
            .customerId(log.getCustomerId())
            .customerName(log.getRecipientName())
            .customerEmail(log.getRecipientEmail())
            .emailOptIn(true)
            .smsOptIn(false).whatsAppOptIn(false)
            .correlationId(log.getCorrelationId())
            .referenceId(log.getReferenceId())
            .referenceType(log.getReferenceType())
            .build();
        return emailService.send(log.getNotificationType(), ctx, log);
    }

    private Mono<Void> rebuildAndSendSms(NotificationLog log) {
        NotificationContext ctx = NotificationContext.builder()
            .customerId(log.getCustomerId())
            .customerName(log.getRecipientName())
            .customerPhone(log.getRecipientPhone())
            .emailOptIn(false).smsOptIn(true).whatsAppOptIn(false)
            .correlationId(log.getCorrelationId())
            .referenceId(log.getReferenceId())
            .referenceType(log.getReferenceType())
            .build();
        return smsService.send(log.getNotificationType(), ctx, log);
    }

    private Mono<Void> rebuildAndSendWhatsApp(NotificationLog log) {
        NotificationContext ctx = NotificationContext.builder()
            .customerId(log.getCustomerId())
            .customerName(log.getRecipientName())
            .customerPhone(log.getRecipientPhone())
            .emailOptIn(false).smsOptIn(false).whatsAppOptIn(true)
            .correlationId(log.getCorrelationId())
            .referenceId(log.getReferenceId())
            .referenceType(log.getReferenceType())
            .build();
        return whatsAppService.send(log.getNotificationType(), ctx, log);
    }

    private NotificationLogResponse toResponse(NotificationLog n) {
        return NotificationLogResponse.builder()
            .id(n.getId())
            .customerId(n.getCustomerId())
            .notificationType(n.getNotificationType())
            .notificationTypeDisplayName(n.getNotificationType().getDisplayName())
            .channel(n.getChannel())
            .status(n.getStatus())
            .statusDescription(n.getStatus().getDescription())
            .subject(n.getSubject())
            .correlationId(n.getCorrelationId())
            .referenceId(n.getReferenceId())
            .referenceType(n.getReferenceType())
            .providerMessageId(n.getProviderMessageId())
            .attempts(n.getAttempts())
            .errorMessage(n.getErrorMessage())
            .lastAttemptAt(n.getLastAttemptAt())
            .deliveredAt(n.getDeliveredAt())
            .createdDate(n.getCreatedDate() != null
                ? n.getCreatedDate().atOffset(java.time.ZoneOffset.UTC) : null)
            .build();
    }
}
