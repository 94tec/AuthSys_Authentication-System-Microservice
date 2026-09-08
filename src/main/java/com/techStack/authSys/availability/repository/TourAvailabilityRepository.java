package com.techStack.authSys.availability.repository;

import com.techStack.authSys.availability.models.AvailabilityStatus;
import com.techStack.authSys.availability.models.TourAvailability;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * TourAvailabilityRepository
 *
 * Caller map — every method traced to its caller:
 *
 *   BookingService.createBooking()        → findById()       [JpaRepository]
 *   BookingService.createBooking()        → save()           [JpaRepository]
 *   BookingService.cancelMyBooking()      → save()           [JpaRepository]
 *   BookingService.cancelBookingByStaff() → save()           [JpaRepository]
 *   BookingService.getBookingsByDate()    → findByDate()
 *
 *   AvailabilityService.createSlot()      → existsByTourIdAndDate, save()
 *   AvailabilityService.getCalendar()     → findByTourIdAndDateBetweenOrderByDateAsc
 *   AvailabilityService.getOpenSlots()    → findByTourIdAndStatusAndDeletedFalse
 *   AvailabilityService.getSlotById()     → findByIdAndDeletedFalse
 *   AvailabilityService.getByTourAndDate()→ findByTourIdAndDate
 *   AvailabilityService.getUpcoming()     → findUpcomingByTour
 *   AvailabilityService.countOpen()       → countUpcomingOpenSlots
 *   AvailabilityService.getAllForTour()   → findByTourIdAndDeletedFalseOrderByDateAsc
 */
@Repository
public interface TourAvailabilityRepository extends JpaRepository<TourAvailability, UUID> {

    // ── BookingService ───────────────────────────────────────────────────────

    /**
     * All slots on a given date across all tours.
     * BookingService.getBookingsByDate() iterates these then fetches bookings per slot.
     */
    List<TourAvailability> findByDate(LocalDate date);

    // ── AvailabilityService ──────────────────────────────────────────────────

    /**
     * All non-deleted slots for a enquire-button.tsx, ascending by date.
     * Used for the staff availability management list.
     */
    List<TourAvailability> findByTourIdAndDeletedFalseOrderByDateAsc(UUID tourId);

    /**
     * Date-range calendar for a enquire-button.tsx.
     * GET /api/availability/enquire-button.tsx/{id}/calendar?from=&to=
     */
    List<TourAvailability> findByTourIdAndDateBetweenOrderByDateAsc(
            UUID tourId, LocalDate from, LocalDate to);

    /**
     * Only OPEN (bookable) slots for a enquire-button.tsx — used by the customer booking form.
     */
    List<TourAvailability> findByTourIdAndStatusAndDeletedFalse(
            UUID tourId, AvailabilityStatus status);

    /**
     * Exact slot by enquire-button.tsx + date (one per enquire-button.tsx per date — unique constraint).
     * Used to prevent duplicate slot creation and for date-specific lookups.
     */
    Optional<TourAvailability> findByTourIdAndDate(UUID tourId, LocalDate date);

    /**
     * Single non-deleted slot by ID.
     * Used by closeSlot(), reopenSlot(), updateSlot().
     */
    Optional<TourAvailability> findByIdAndDeletedFalse(UUID id);

    /**
     * Duplicate slot guard — checked before createSlot() persists.
     */
    boolean existsByTourIdAndDate(UUID tourId, LocalDate date);

    /**
     * Upcoming OPEN slots from a given date — public booking calendar.
     */
    @Query("""
            SELECT a FROM TourAvailability a
            WHERE a.tour.id = :tourId
              AND a.deleted  = false
              AND a.date    >= :from
            ORDER BY a.date ASC
            """)
    List<TourAvailability> findUpcomingByTour(
            @Param("tourId") UUID tourId,
            @Param("from")   LocalDate from);

    /**
     * Count of upcoming open slots — admin dashboard stat card.
     */
    @Query("""
            SELECT COUNT(a) FROM TourAvailability a
            WHERE a.tour.id = :tourId
              AND a.status   = com.techStack.authSys.availability.models.AvailabilityStatus.OPEN
              AND a.deleted  = false
              AND a.date    >= CURRENT_DATE
            """)
    long countUpcomingOpenSlots(@Param("tourId") UUID tourId);
}
