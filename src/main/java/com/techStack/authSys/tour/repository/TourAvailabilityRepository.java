package com.techStack.authSys.tour.repositories;

import com.techStack.authSys.tour.models.AvailabilityStatus;
import com.techStack.authSys.tour.models.TourAvailability;
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
 * Method inventory — every caller mapped:
 *
 *  BookingService.createBooking()       → findById()          [inherited]
 *  BookingService.createBooking()       → save()              [inherited]
 *  BookingService.cancelMyBooking()     → save()              [inherited]
 *  BookingService.cancelBookingByStaff()→ save()              [inherited]
 *  BookingService.getBookingsByDate()   → findByDate()
 *
 *  AvailabilityService.getCalendar()    → findByTourIdAndDateBetweenOrderByDateAsc
 *  AvailabilityService.getOpen()        → findByTourIdAndStatusAndDeletedFalse
 *  AvailabilityService.closeSlot()      → findByIdAndDeletedFalse
 *  AvailabilityService.getByTourAndDate → findByTourIdAndDate
 */
@Repository
public interface TourAvailabilityRepository extends JpaRepository<TourAvailability, UUID> {

    // ── Called by BookingService ─────────────────────────────────────────────

    /**
     * All availability slots for a given date, across all tours.
     * Used by BookingService.getBookingsByDate() to build the daily manifest —
     * iterates slots, then fetches bookings per slot.
     */
    List<TourAvailability> findByDate(LocalDate date);

    // ── Called by AvailabilityService / AvailabilityController ───────────────

    /**
     * All non-deleted slots for a tour, ordered by date ascending.
     * Used for the booking calendar and the availability management list.
     */
    List<TourAvailability> findByTourIdAndDeletedFalseOrderByDateAsc(UUID tourId);

    /**
     * Date-range calendar view for a specific tour.
     * Used by GET /api/availability/tour/{id}/calendar?from=&to=
     */
    List<TourAvailability> findByTourIdAndDateBetweenOrderByDateAsc(
            UUID tourId, LocalDate from, LocalDate to);

    /**
     * All open slots for a tour (status = OPEN, not deleted).
     * Used to show only bookable dates on the booking form.
     */
    List<TourAvailability> findByTourIdAndStatusAndDeletedFalse(
            UUID tourId, AvailabilityStatus status);

    /**
     * Single slot by tour + date (unique constraint).
     * Used to prevent duplicate slot creation and for specific-date lookups.
     */
    Optional<TourAvailability> findByTourIdAndDate(UUID tourId, LocalDate date);

    /**
     * Single non-deleted slot by ID.
     * Used by AvailabilityService.closeSlot(), AvailabilityService.reopenSlot().
     */
    Optional<TourAvailability> findByIdAndDeletedFalse(UUID id);

    /**
     * Check if a slot already exists for this tour + date.
     * Used in AvailabilityService.createSlot() to prevent duplicates.
     */
    boolean existsByTourIdAndDate(UUID tourId, LocalDate date);

    /**
     * Count open slots for a tour — admin dashboard stat.
     */
    @Query("""
            SELECT COUNT(a) FROM TourAvailability a
            WHERE a.tour.id = :tourId
              AND a.status  = 'OPEN'
              AND a.deleted = false
              AND a.date   >= CURRENT_DATE
            """)
    long countUpcomingOpenSlots(@Param("tourId") UUID tourId);

    /**
     * All upcoming non-deleted slots for a tour (today and forward).
     * Used for the public-facing booking calendar.
     */
    @Query("""
            SELECT a FROM TourAvailability a
            WHERE a.tour.id = :tourId
              AND a.deleted = false
              AND a.date   >= :from
            ORDER BY a.date ASC
            """)
    List<TourAvailability> findUpcomingByTour(
            @Param("tourId") UUID tourId,
            @Param("from")   LocalDate from);
}
