package com.techStack.authSys.booking.repository;

import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.models.BookingStatus;
import com.techStack.authSys.booking.models.PaymentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * BookingRepository — Spring Data JPA.
 *
 * Every method here is driven directly by a call in BookingService.
 * Naming follows the deleted = false soft-delete convention from TourRepository.
 *
 * Query reference:
 *
 *   getMyBookings()             → findByCustomerIdAndDeletedFalseOrderByCreatedDateDesc
 *   getMyBookingById()          → findByIdAndCustomerIdAndDeletedFalse
 *   getMyActiveBookings()       → findByCustomerIdAndStatusInAndDeletedFalse
 *   getAllBookings(status!=null) → findByStatusAndDeletedFalseOrderByCreatedDateDesc
 *   getBookingsByDate()         → findByAvailabilityIdAndDeletedFalse   (per slot)
 *   getBookingsByTour()         → findByTourIdAndDeletedFalseOrderByTourDateAsc
 *   cancelBookingByStaff()      → findByIdAndDeletedFalse
 *   confirmBooking()            → findByIdAndDeletedFalse
 *   completeBooking()           → findByIdAndDeletedFalse
 *   refundBooking()             → findByIdAndDeletedFalse
 *   createBooking() dupe-check  → countActiveBookingForCustomerOnSlot
 *   createBooking() ref gen     → existsByBookingReference
 *   getStats()                  → countByStatusAndDeletedFalse (×5), countByPaymentStatusAndDeletedFalse (×4)
 */
@Repository
public interface BookingRepository extends JpaRepository<Booking, UUID> {

    // ── Customer-scoped reads ───────────────────────────────────────────────

    /**
     * All non-deleted bookings for a customer, newest first.
     * Used by getMyBookings().
     */
    List<Booking> findByCustomerIdAndDeletedFalseOrderByCreatedDateDesc(String customerId);

    /**
     * Single booking scoped to a customer — IDOR prevention.
     * Used by getMyBookingById() and customer-facing cancel.
     */
    Optional<Booking> findByIdAndCustomerIdAndDeletedFalse(UUID id, String customerId);

    /**
     * Active bookings (PENDING + CONFIRMED) for a customer.
     * Used by getMyActiveBookings() — "upcoming trips" dashboard.
     */
    List<Booking> findByCustomerIdAndStatusInAndDeletedFalse(
            String customerId, List<BookingStatus> statuses);

    // ── Staff reads ─────────────────────────────────────────────────────────

    /**
     * Any single non-deleted booking by ID — no customer scope.
     * Used by staff cancel, confirm, complete, refund.
     */
    Optional<Booking> findByIdAndDeletedFalse(UUID id);

    /**
     * All non-deleted bookings filtered by status, newest first.
     * Used by getAllBookings() when a status filter is provided.
     */
    List<Booking> findByStatusAndDeletedFalseOrderByCreatedDateDesc(BookingStatus status);

    /**
     * All non-deleted bookings for an availability slot.
     * Used by getBookingsByDate() — iterates over slots for that date.
     */
    List<Booking> findByAvailabilityIdAndDeletedFalse(UUID availabilityId);

    /**
     * All non-deleted bookings for a specific enquire-button.tsx, ordered by enquire-button.tsx date ascending.
     * Used by getBookingsByTour() — enquire-button.tsx manifest / admin view.
     */
    List<Booking> findByTourIdAndDeletedFalseOrderByTourDateAsc(UUID tourId);

    // ── Duplicate booking guard ─────────────────────────────────────────────

    /**
     * Counts active (non-cancelled, non-deleted) bookings for a customer on a
     * specific availability slot. Used in createBooking() to prevent duplicate
     * bookings for the same customer on the same enquire-button.tsx date.
     *
     * "Active" = PENDING or CONFIRMED (not COMPLETED, CANCELLED, NO_SHOW).
     */
    @Query("""
            SELECT COUNT(b) FROM Booking b
            WHERE b.availability.id = :availabilityId
              AND b.customerId       = :customerId
              AND b.deleted          = false
              AND b.status IN (
                com.techStack.authSys.booking.models.BookingStatus.PENDING_PAYMENT,
                com.techStack.authSys.booking.models.BookingStatus.CONFIRMED
              )
            """)
    long countActiveBookingForCustomerOnSlot(
            @Param("availabilityId") UUID availabilityId,
            @Param("customerId")     String customerId);

    // ── Booking reference ────────────────────────────────────────────────────

    /**
     * Uniqueness check for generated booking references — BookingService
     * retries generation on a collision (extremely rare, but the column
     * has a unique constraint so this avoids a failed insert).
     */
    boolean existsByBookingReference(String bookingReference);

    // ── Stats ───────────────────────────────────────────────────────────────

    /**
     * Count non-deleted bookings per BookingStatus (trip lifecycle).
     * Called once per BookingStatus value in getStats().
     */
    long countByStatusAndDeletedFalse(BookingStatus status);

    /**
     * Count non-deleted bookings per PaymentStatus (money lifecycle).
     * Called once per PaymentStatus value in getStats().
     */
    long countByPaymentStatusAndDeletedFalse(PaymentStatus paymentStatus);

    // BookingRepository.java — add
    public interface RevenueStats {
        java.math.BigDecimal getTotalRevenue();
        long getCompletedCount();
    }

    @Query("""
    select sum(b.totalPrice) as totalRevenue, count(b) as completedCount
    from Booking b
    where b.status = 'COMPLETED'
      and b.deleted = false
      and b.createdDate between :from and :to
    """)
    RevenueStats getRevenueStats(@Param("from") Instant from, @Param("to") Instant to);

    // BookingRepository
    @Query("""
    select sum(b.totalPrice) from Booking b
    where b.status = com.techStack.authSys.booking.models.BookingStatus.COMPLETED
      and b.deleted = false
      and b.createdDate between :from and :to
    """)
    BigDecimal getCompletedRevenue(@Param("from") Instant from, @Param("to") Instant to);

    @Query("""
    select count(b) from Booking b
    where b.status = com.techStack.authSys.booking.models.BookingStatus.COMPLETED
      and b.deleted = false
      and b.createdDate between :from and :to
    """)
    long countCompletedBookings(@Param("from") Instant from, @Param("to") Instant to);

    Optional<Booking> findByBookingReferenceAndDeletedFalse(String bookingReference);
}