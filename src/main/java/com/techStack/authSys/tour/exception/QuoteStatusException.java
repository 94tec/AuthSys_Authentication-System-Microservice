package com.techStack.authSys.tour.exception;

import com.techStack.authSys.tour.models.QuoteStatus;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

@Getter
public class QuoteStatusException extends RuntimeException {

    private final UUID quoteId;
    private final QuoteStatus currentStatus;
    private final Set<QuoteStatus> allowedStatuses;
    private final String action;
    private final HttpStatus status;

    public QuoteStatusException(
            UUID quoteId,
            QuoteStatus currentStatus,
            Set<QuoteStatus> allowedStatuses,
            String action
    ) {
        this(
                quoteId,
                currentStatus,
                allowedStatuses,
                action,
                HttpStatus.CONFLICT
        );
    }

    public QuoteStatusException(
            UUID quoteId,
            QuoteStatus currentStatus,
            Set<QuoteStatus> allowedStatuses,
            String action,
            HttpStatus status
    ) {
        super(buildMessage(
                quoteId,
                currentStatus,
                allowedStatuses,
                action
        ));

        this.quoteId = quoteId;
        this.currentStatus = currentStatus;
        this.allowedStatuses = allowedStatuses == null
                ? Collections.emptySet()
                : Collections.unmodifiableSet(
                new LinkedHashSet<>(allowedStatuses)
        );
        this.action = action == null || action.isBlank()
                ? "perform this action on"
                : action;
        this.status = status == null
                ? HttpStatus.CONFLICT
                : status;
    }

    public HttpStatus status() {
        return status;
    }

    private static String buildMessage(
            UUID quoteId,
            QuoteStatus currentStatus,
            Set<QuoteStatus> allowedStatuses,
            String action
    ) {
        String safeAction =
                action == null || action.isBlank()
                        ? "perform this action on"
                        : action;

        if (quoteId == null) {
            return "Cannot "
                    + safeAction
                    + " quote because the quote does not exist.";
        }

        if (currentStatus == null) {
            return "Cannot "
                    + safeAction
                    + " quote "
                    + quoteId
                    + " because it has no valid status.";
        }

        Set<QuoteStatus> safeAllowedStatuses =
                allowedStatuses == null
                        ? Collections.emptySet()
                        : allowedStatuses;

        if (safeAllowedStatuses.isEmpty()) {
            return "Cannot "
                    + safeAction
                    + " quote "
                    + quoteId
                    + " because its current status is "
                    + currentStatus
                    + ".";
        }

        return "Cannot "
                + safeAction
                + " quote "
                + quoteId
                + " because its current status is "
                + currentStatus
                + ". Allowed statuses: "
                + safeAllowedStatuses
                + ".";
    }
}