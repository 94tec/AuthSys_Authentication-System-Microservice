package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Value;
import org.springframework.http.HttpStatus;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Map;

@Value
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    HttpStatus status;
    String errorCode;
    String message;
    String field;
    Map<String, Object> details;
    Instant timestamp;
    String traceId;
    String severity;

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

    // Backward compatibility alias
    public Map<String, Object> getAdditionalInfo() {
        return details;
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
