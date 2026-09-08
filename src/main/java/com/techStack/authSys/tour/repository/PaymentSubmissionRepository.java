package com.techStack.authSys.tour.repository;

import com.techStack.authSys.tour.models.PaymentSubmission;
import com.techStack.authSys.tour.models.PaymentSubmissionStatus;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PaymentSubmissionRepository extends JpaRepository<PaymentSubmission, UUID> {

    boolean existsByQuoteIdAndStatus(UUID quoteId, PaymentSubmissionStatus status);

    @Query(value = """
        select p from PaymentSubmission p
        join fetch p.quote q
        join fetch q.enquiry e
        join fetch e.tour t
        where p.status = :status
        order by p.createdDate asc
        """,
            countQuery = "select count(p) from PaymentSubmission p where p.status = :status")
    Page<PaymentSubmission> findAllByStatus(@Param("status") PaymentSubmissionStatus status, Pageable pageable);

    /** VERIFIED payments that don't have a booking yet, i.e. admin still has to create it. */
    @Query(value = """
        select p from PaymentSubmission p
        join fetch p.quote q
        join fetch q.enquiry e
        join fetch e.tour t
        where p.status = com.techStack.authSys.tour.models.PaymentSubmissionStatus.VERIFIED
          and e.bookingReference is null
        order by p.verifiedAt asc
        """,
            countQuery = """
        select count(p) from PaymentSubmission p
        where p.status = com.techStack.authSys.tour.models.PaymentSubmissionStatus.VERIFIED
          and p.quote.enquiry.bookingReference is null
        """)
    Page<PaymentSubmission> findVerifiedAwaitingBooking(Pageable pageable);

    @Query("""
        select p from PaymentSubmission p
        join fetch p.quote q
        join fetch q.enquiry e
        join fetch e.tour t
        where e.id = :enquiryId
        order by p.createdDate desc
        """)
    List<PaymentSubmission> findAllByEnquiryId(@Param("enquiryId") UUID enquiryId);

    @Query("""
        select p from PaymentSubmission p
        join fetch p.quote q
        join fetch q.enquiry e
        join fetch e.tour t
        where p.id = :id
        """)
    Optional<PaymentSubmission> findByIdWithQuote(@Param("id") UUID id);
}