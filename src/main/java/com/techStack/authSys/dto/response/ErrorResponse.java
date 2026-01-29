package com.techStack.authSys.dto.response;

import org.springframework.http.HttpStatus;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.io.Serializable;
import java.util.Map;

/**
 * Standardized error response DTO for all API errors
 * Provides consistent error structure across the application
 */
@JsonInclude(JsonInclude.Include.NON_NULL) // Don't include null fields in JSON
public class ErrorResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    private final HttpStatus status;
    private final String errorCode;
    private final String message;
    private final String field;
    private final Map<String, Object> additionalInfo;
    private final long timestamp;

    /**
     * Full constructor
     */
    public ErrorResponse(HttpStatus status, String errorCode, String message,
                         String field, Map<String, Object> additionalInfo) {
        this.status = status;
        this.errorCode = errorCode;
        this.message = message;
        this.field = field;
        this.additionalInfo = additionalInfo;
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Constructor without field
     */
    public ErrorResponse(HttpStatus status, String errorCode, String message,
                         Map<String, Object> additionalInfo) {
        this(status, errorCode, message, null, additionalInfo);
    }

    /**
     * Simple constructor
     */
    public ErrorResponse(HttpStatus status, String errorCode, String message) {
        this(status, errorCode, message, null, null);
    }

    // Getters
    public HttpStatus getStatus() {
        return status;
    }

    public int getStatusCode() {
        return status.value();
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getMessage() {
        return message;
    }

    public String getField() {
        return field;
    }

    public Map<String, Object> getAdditionalInfo() {
        return additionalInfo;
    }

    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Check if error is retryable
     */
    public boolean isRetryable() {
        if (additionalInfo != null && additionalInfo.containsKey("retryable")) {
            return (boolean) additionalInfo.get("retryable");
        }
        return false;
    }

    /**
     * Check if user should contact support
     */
    public boolean shouldContactSupport() {
        if (additionalInfo != null && additionalInfo.containsKey("contactSupport")) {
            return (boolean) additionalInfo.get("contactSupport");
        }
        return false;
    }

    /**
     * Get retry after minutes (if applicable)
     */
    public Integer getRetryAfterMinutes() {
        if (additionalInfo != null && additionalInfo.containsKey("retryAfter")) {
            Object value = additionalInfo.get("retryAfter");
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
                ", timestamp=" + timestamp +
                '}';
    }
}