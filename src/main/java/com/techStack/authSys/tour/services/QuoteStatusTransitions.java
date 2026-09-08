package com.techStack.authSys.tour.services;

import com.techStack.authSys.tour.exception.QuoteStatusException;
import com.techStack.authSys.tour.models.EnquiryQuote;
import com.techStack.authSys.tour.models.QuoteStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@Slf4j
public class QuoteStatusTransitions {

    /**
     * Quote can only be sent when it is still a draft.
     */
    public void assertCanSend(EnquiryQuote quote) {
        assertStatus(
                quote,
                Set.of(QuoteStatus.DRAFT),
                "send"
        );
    }

    /**
     * Customer can only accept a quote that has been sent.
     */
    public void assertCanAccept(EnquiryQuote quote) {
        assertStatus(
                quote,
                Set.of(QuoteStatus.SENT),
                "accept"
        );
    }

    /**
     * Customer can only reject a quote that has been sent.
     */
    public void assertCanReject(EnquiryQuote quote) {
        assertStatus(
                quote,
                Set.of(QuoteStatus.SENT),
                "reject"
        );
    }

    /**
     * Staff can cancel drafts or previously sent quotes.
     */
    public void assertCanCancel(EnquiryQuote quote) {
        assertStatus(
                quote,
                Set.of(
                        QuoteStatus.DRAFT,
                        QuoteStatus.SENT
                ),
                "cancel"
        );
    }

    /**
     * System can expire quotes that have been sent
     * but not yet accepted.
     */
    public void assertCanExpire(EnquiryQuote quote) {
        assertStatus(
                quote,
                Set.of(QuoteStatus.SENT),
                "expire"
        );
    }

    /**
     * Generic transition validator.
     */
    private void assertStatus(
            EnquiryQuote quote,
            Set<QuoteStatus> allowedStatuses,
            String action
    ) {

        if (quote == null) {
            log.warn(
                    "Attempted to {} a null quote. Allowed statuses={}",
                    action,
                    allowedStatuses
            );

            throw new QuoteStatusException(
                    null,
                    null,
                    allowedStatuses,
                    action
            );
        }

        QuoteStatus currentStatus = quote.getStatus();

        if (currentStatus == null) {
            log.warn(
                    "Quote {} has null status. Action={}, Allowed={}",
                    quote.getId(),
                    action,
                    allowedStatuses
            );

            throw new QuoteStatusException(
                    quote.getId(),
                    null,
                    allowedStatuses,
                    action
            );
        }

        if (!allowedStatuses.contains(currentStatus)) {
            log.warn(
                    "Invalid quote transition. Quote={}, Action={}, CurrentStatus={}, AllowedStatuses={}",
                    quote.getId(),
                    action,
                    currentStatus,
                    allowedStatuses
            );

            throw new QuoteStatusException(
                    quote.getId(),
                    currentStatus,
                    allowedStatuses,
                    action
            );
        }

        log.debug(
                "Quote transition validated. Quote={}, Action={}, Status={}",
                quote.getId(),
                action,
                currentStatus
        );
    }
}

