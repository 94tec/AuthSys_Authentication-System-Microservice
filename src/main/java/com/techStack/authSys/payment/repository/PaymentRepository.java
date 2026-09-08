package com.techStack.authSys.payment.repository;

import com.techStack.authSys.payment.models.Payment;
import com.techStack.authSys.payment.models.PaymentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * PaymentRepository
 *
 * Caller map:
 *   MpesaService.initiateStkPush()        → save()                     [inherited]
 *   PaymentService.handleMpesaCallback()  → findByCheckoutRequestId
 *   PaymentService.handleMpesaCallback()  → save()                     [inherited]
 *   PaymentService.getPaymentsByBooking() → findByBookingIdOrderByInitiatedAtDesc
 *   PaymentService.getSuccessPayment()    → findByBookingIdAndStatus
 *   PaymentService.getByCustomer()        → findByCustomerIdOrderByInitiatedAtDesc
 *   PaymentController.getById()           → findById()                  [inherited]
 *   PaymentService.getStats()             → countByStatus (×5), sumSuccessAmount
 */
@Repository
public interface PaymentRepository extends JpaRepository<Payment, UUID> {

    // ── Callback matching ─────────────────────────────────────────────────────

    /**
     * Look up a pending Payment by the Safaricom CheckoutRequestID.
     * This is the key used to match the async STK callback to the correct row.
     * Called immediately in PaymentService.handleMpesaCallback().
     */
    Optional<Payment> findByCheckoutRequestId(String checkoutRequestId);

    // ── Booking-scoped reads ──────────────────────────────────────────────────

    /**
     * All payments for a booking, newest first.
     * A booking may have multiple rows if first attempt failed and customer retried.
     */
    List<Payment> findByBookingIdOrderByInitiatedAtDesc(UUID bookingId);

    /**
     * The successful payment for a booking — for receipts and admin views.
     * Should return 0 or 1 results (only one SUCCESS per booking).
     */
    Optional<Payment> findByBookingIdAndStatus(UUID bookingId, PaymentStatus status);

    // ── Customer-scoped reads ─────────────────────────────────────────────────

    /**
     * All payments by a customer — payment history view.
     */
    List<Payment> findByCustomerIdOrderByInitiatedAtDesc(String customerId);

    // ── Admin stats ───────────────────────────────────────────────────────────

    /**
     * Count payments per status — dashboard stat card.
     * Called ×5 in getStats(), once per PaymentStatus value.
     */
    long countByStatus(PaymentStatus status);

    /**
     * Total KES collected from successful payments.
     * Used for revenue reporting on the admin dashboard.
     * Returns 0 if no successful payments exist.
     */
    @Query("""
            SELECT COALESCE(SUM(p.amount), 0)
            FROM Payment p
            WHERE p.status = com.techStack.authSys.payment.models.PaymentStatus.SUCCESS
            """)
    java.math.BigDecimal sumSuccessfulAmount();

    /**
     * Total revenue for a specific enquire-button.tsx — joins through Booking.
     * Used by admin enquire-button.tsx-level revenue reporting.
     */
    @Query("""
            SELECT COALESCE(SUM(p.amount), 0)
            FROM Payment p
            WHERE p.status     = com.techStack.authSys.payment.models.PaymentStatus.SUCCESS
              AND p.booking.tour.id = :tourId
            """)
    java.math.BigDecimal sumSuccessfulAmountByTour(@Param("tourId") UUID tourId);

    /**
     * Existence check — does a SUCCESS payment already exist for this booking?
     * Guard in PaymentService to prevent double-confirming.
     */
    boolean existsByBookingIdAndStatus(UUID bookingId, PaymentStatus status);
}
