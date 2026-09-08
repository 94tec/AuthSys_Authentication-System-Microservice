package com.techStack.authSys.tour.repository;

import com.techStack.authSys.tour.models.EnquiryQuote;
import com.techStack.authSys.tour.models.QuoteStatus;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EnquiryQuoteRepository extends JpaRepository<EnquiryQuote, UUID> {
    List<EnquiryQuote> findAllByEnquiryIdOrderByCreatedDateDesc(UUID enquiryId);
    Optional<EnquiryQuote> findByIdAndEnquiryId(UUID id, UUID enquiryId);
    List<EnquiryQuote> findAllByStatusAndValidUntilBefore(QuoteStatus status, LocalDate date);

    @Query("""
        select sum(q.totalPrice) from EnquiryQuote q
        where q.status in (
            com.techStack.authSys.tour.models.QuoteStatus.SENT,
            com.techStack.authSys.tour.models.QuoteStatus.ACCEPTED
        )
        and q.deleted = false
        and q.createdDate between :from and :to
        """)
    BigDecimal getOpenPipelineValue(@Param("from") Instant from, @Param("to") Instant to);
}