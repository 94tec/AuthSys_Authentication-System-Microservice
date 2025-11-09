package com.techStack.authSys.util;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.exception.CustomException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.concurrent.TimeoutException;

@Component
@Slf4j
public class RetryUtils {

    /**
     * Checks if a given Throwable represents a transient error suitable for a retry.
     * @param throwable The error to check.
     * @return true if the error is retryable, false otherwise.
     */
    public boolean isRetryableError(Throwable throwable) {
        boolean retryable = false;

        if (throwable instanceof CustomException custom) {
            // Check if CustomException has a status and it's a 5xx error
            retryable = custom.getStatus() != null && custom.getStatus().is5xxServerError();
        } else if (throwable instanceof TimeoutException ||
                throwable instanceof java.net.ConnectException ||
                throwable instanceof java.net.SocketTimeoutException ||
                // WebClientRequestException often covers network issues and connection failures
                throwable instanceof org.springframework.web.reactive.function.client.WebClientRequestException) {
            retryable = true;
        } else if (throwable instanceof FirebaseAuthException fae) {
            //String errorCode = fae.getErrorCode() != null ? fae.getErrorCode() : "";
            // FIX: Convert ErrorCode object to String using .name()
            String errorCode = fae.getErrorCode() != null ? fae.getErrorCode().name() : "";
            int status = fae.getHttpResponse() != null ? fae.getHttpResponse().getStatusCode() : -1;
            // Retry on 5xx status or specific Firebase internal/unavailable error codes
            retryable = (status >= 500) ||
                    "INTERNAL_ERROR".equalsIgnoreCase(errorCode) ||
                    "UNAVAILABLE".equalsIgnoreCase(errorCode) ||
                    "UNKNOWN".equalsIgnoreCase(errorCode);
        } else if (throwable instanceof ResponseStatusException rse) {
            // Retry on 5xx status from a ResponseStatusException
            retryable = rse.getStatusCode().is5xxServerError();
        }

        log.debug("Retry check for [{}] → {}", throwable.getClass().getSimpleName(), retryable);
        return retryable;
    }
}