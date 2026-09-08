package com.techStack.authSys.tour.repository;

import com.techStack.authSys.tour.models.TourEnquiry;
import com.techStack.authSys.tour.models.TourEnquiryStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

public interface TourEnquiryRepository extends JpaRepository<TourEnquiry, UUID> {

    @Query("""
    select e from TourEnquiry e
    left join fetch e.tour
    where e.id = :id
      and e.deleted = false
    """)
    Optional<TourEnquiry> findByIdAndDeletedFalse(@Param("id") UUID id);

    Page<TourEnquiry> findAllByTourIdAndDeletedFalse(UUID tourId, Pageable pageable);

    @Query("""
    select e from TourEnquiry e
    left join fetch e.tour
    where e.userId = :userId
      and e.deleted = false
    """)
    Page<TourEnquiry> findAllByUserIdAndDeletedFalse(@Param("userId") String userId, Pageable pageable);

    @Query("""
    select e from TourEnquiry e
    left join fetch e.tour
    where e.userId = :userId
      and e.status = :status
      and e.deleted = false
    """)
    Page<TourEnquiry> findAllByUserIdAndStatusAndDeletedFalse(
            @Param("userId") String userId,
            @Param("status") TourEnquiryStatus status,
            Pageable pageable);
    long countByTourId(UUID tourId);

    boolean existsByTourIdAndUserIdAndCreatedDateAfter(UUID tourId, String userId, Instant since);

    // ── Admin filtered search ──────────────────────────────
    @Query(value = """
    select e from TourEnquiry e
    left join fetch e.tour t
    where e.deleted = false
      and (cast(:status as string) is null or e.status = :status)
      and (cast(:assignedTo as string) is null or e.assignedTo = :assignedTo)
      and (cast(:tourId as string) is null or e.tour.id = :tourId)
      and (cast(:search as string) is null
           or lower(e.fullName) like lower(concat('%', cast(:search as string), '%'))
           or lower(e.email) like lower(concat('%', cast(:search as string), '%')))
    """,
            countQuery = """
                select count(e) from TourEnquiry e
                where e.deleted = false
                  and (cast(:status as string) is null or e.status = :status)
                  and (cast(:assignedTo as string) is null or e.assignedTo = :assignedTo)
                  and (cast(:tourId as string) is null or e.tour.id = :tourId)
                  and (cast(:search as string) is null
                       or lower(e.fullName) like lower(concat('%', cast(:search as string), '%'))
                       or lower(e.email) like lower(concat('%', cast(:search as string), '%')))
                """)
    Page<TourEnquiry> search(
            @Param("status") TourEnquiryStatus status,
            @Param("assignedTo") String assignedTo,
            @Param("tourId") UUID tourId,
            @Param("search") String search,
            Pageable pageable);
    // ── Staff queues ────────────────────────────────────────
    Page<TourEnquiry> findAllByStatusAndAssignedToIsNullAndDeletedFalse(
            TourEnquiryStatus status, Pageable pageable);

    @Query("""
        select e from TourEnquiry e
        where e.deleted = false
          and e.status in :statuses
          and e.lastModifiedDate < :cutoff
        """)
    Page<TourEnquiry> findOverdueFollowUp(
            @Param("statuses") java.util.List<TourEnquiryStatus> statuses,
            @Param("cutoff") Instant cutoff,
            Pageable pageable);

    @Query("""
        select e from TourEnquiry e
        where e.deleted = false
          and e.status = com.techStack.authSys.tour.models.TourEnquiryStatus.CONVERTED
          and e.travelStartDate between :from and :to
        """)
    Page<TourEnquiry> findUpcomingDepartures(
            @Param("from") LocalDate from, @Param("to") LocalDate to, Pageable pageable);

    @Query("""
        select e from TourEnquiry e
        where e.deleted = false
          and e.status = com.techStack.authSys.tour.models.TourEnquiryStatus.CONVERTED
          and e.travelEndDate <= :today
          and e.appreciationSentAt is null
        """)
    java.util.List<TourEnquiry> findEligibleForAppreciation(@Param("today") LocalDate today);

    // ── Dashboard counts ────────────────────────────────────
    long countByStatus(TourEnquiryStatus status);
    long countByStatusAndAssignedToIsNull(TourEnquiryStatus status);

    @Query("""
    select sum(q.totalPrice)
    from EnquiryQuote q
    where q.status in ('SENT', 'ACCEPTED')
      and q.deleted = false
      and q.createdDate between :from and :to
    """)
    BigDecimal getExpectedRevenue(@Param("from") Instant from, @Param("to") Instant to);

    @Query("""
    select count(e) from TourEnquiry e
    where e.deleted = false and e.createdDate between :from and :to
    """)
    long countCreatedBetween(@Param("from") Instant from, @Param("to") Instant to);
}