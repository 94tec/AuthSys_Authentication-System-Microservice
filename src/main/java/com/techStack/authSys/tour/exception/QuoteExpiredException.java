package com.techStack.authSys.tour.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.LocalDate;
import java.util.UUID;

@Getter
public class QuoteExpiredException extends RuntimeException {

    private final UUID quoteId;
    private final LocalDate expiredOn;

    public QuoteExpiredException(
            UUID quoteId,
            LocalDate expiredOn
    ) {
        super(
                "This quote expired on "
                        + expiredOn
                        + ". Please contact us for an updated quote."
        );

        this.quoteId = quoteId;
        this.expiredOn = expiredOn;
    }

    public HttpStatus status() {
        return HttpStatus.CONFLICT;
    }
}