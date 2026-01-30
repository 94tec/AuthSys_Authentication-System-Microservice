package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Value;
import org.springframework.http.HttpStatus;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;

/**
 * Standardized error response DTO for all API errors.
 * Provides consistent error structure across the application.
 */
@Value // Immutable DTO
@Builder // Builder pattern for consistency with service usage
@JsonInclude(JsonInclude.Include.NON_NULL) // Don't include null fields in JSON
public class ErrorResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    HttpStatus status;                  // HTTP status
    String errorCode;                   // Application-specific error code
    String message;                     // Human-readable error message
    String field;                       // Field causing the error (optional)
    Map<String, Object> details;        // Extra metadata (renamed from additionalInfo)
    Instant timestamp;                     // Error occurrence time
    String traceId;                     // Correlation/trace ID for debugging
    String severity;                    // Severity level: INFO, WARN, ERROR, CRITICAL

    /**
     * Convenience methods
     */
    public int getStatusCode() {
        return status.value();
    }

    public boolean isRetryable() {
        return details != null && Boolean.TRUE.equals(details.get("retryable"));
    }

    public boolean shouldContactSupport() {
        return details != null && Boolean.TRUE.equals(details.get("contactSupport"));
    }

    public Integer getRetryAfterMinutes() {
        if (details != null && details.containsKey("retryAfter")) {
            Object value = details.get("retryAfter");
            if (value instanceof Integer) {
                return (Integer) value;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return "ErrorResponse{" +
                "status=" + status +
                ", errorCode='" + errorCode + '\'' +
                ", message='" + message + '\'' +
                ", field='" + field + '\'' +
                ", severity='" + severity + '\'' +
                ", traceId='" + traceId + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}
