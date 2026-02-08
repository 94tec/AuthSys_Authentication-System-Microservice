package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

/**
 * Standardized API Response Wrapper
 *
 * Provides consistent response structure across all API endpoints.
 * Uses Instant for timestamp tracking (Clock-compatible).
 *
 * @param <T> Type of the data in success response
 */
@Setter
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /* =========================
       Response Fields
       ========================= */

    private boolean success;
    private String message;
    private T data;
    private Instant timestamp;
    private Long timestampMillis; // For backward compatibility

    /* =========================
       Constructors
       ========================= */

    /**
     * Default constructor with current timestamp
     */
    public ApiResponse() {
        this.timestamp = Instant.now();
        this.timestampMillis = this.timestamp.toEpochMilli();
    }

    /**
     * Full constructor
     */
    public ApiResponse(boolean success, String message, T data) {
        this.success = success;
        this.message = message;
        this.data = data;
        this.timestamp = Instant.now();
        this.timestampMillis = this.timestamp.toEpochMilli();
    }

    /**
     * Constructor with explicit timestamp (Clock-based)
     */
    public ApiResponse(boolean success, String message, T data, Instant timestamp) {
        this.success = success;
        this.message = message;
        this.data = data;
        this.timestamp = timestamp;
        this.timestampMillis = timestamp.toEpochMilli();
    }

    /* =========================
       Success Factory Methods
       ========================= */

    /**
     * Success with typed data
     */
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, "Operation successful", data);
    }

    /**
     * Success with typed data and custom message
     */
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }

    /**
     * Success with typed data and explicit timestamp
     */
    public static <T> ApiResponse<T> success(String message, T data, Instant timestamp) {
        return new ApiResponse<>(true, message, data, timestamp);
    }

    /**
     * Success with message but no data
     */
    public static ApiResponse<Void> success(String message) {
        return new ApiResponse<>(true, message, null);
    }

    /**
     * Success with message and explicit timestamp
     */
    public static ApiResponse<Void> success(String message, Instant timestamp) {
        return new ApiResponse<>(true, message, null, timestamp);
    }

    /**
     * Default success with no data or message
     */
    public static ApiResponse<Void> success() {
        return new ApiResponse<>(true, "Operation successful", null);
    }

    /* =========================
       Error Factory Methods
       ========================= */

    /**
     * Error response (no generics, safe for all paths)
     */
    public static ApiResponse<Void> error(String message) {
        return new ApiResponse<>(false, message, null);
    }

    /**
     * Error response with explicit timestamp
     */
    public static ApiResponse<Void> error(String message, Instant timestamp) {
        return new ApiResponse<>(false, message, null, timestamp);
    }

    /**
     * Error response with data (e.g., validation errors)
     */
    public static <T> ApiResponse<T> error(String message, T data) {
        return new ApiResponse<>(false, message, data);
    }

    /**
     * Error response with data and explicit timestamp
     */
    public static <T> ApiResponse<T> error(String message, T data, Instant timestamp) {
        return new ApiResponse<>(false, message, data, timestamp);
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Check if response is successful
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Check if response is error
     */
    public boolean isError() {
        return !success;
    }

    /**
     * Get timestamp as epoch millis
     */
    public long getTimestampMillis() {
        return timestampMillis != null ? timestampMillis :
                (timestamp != null ? timestamp.toEpochMilli() : 0L);
    }

    /**
     * Get timestamp as ISO-8601 string
     */
    public String getTimestampISO() {
        return timestamp != null ? timestamp.toString() : null;
    }

    /* =========================
       Object Methods
       ========================= */

    @Override
    public String toString() {
        return "ApiResponse{" +
                "success=" + success +
                ", message='" + message + '\'' +
                ", data=" + data +
                ", timestamp=" + timestamp +
                ", timestampMillis=" + timestampMillis +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ApiResponse<?> that = (ApiResponse<?>) o;

        if (success != that.success) return false;
        if (!message.equals(that.message)) return false;
        if (data != null ? !data.equals(that.data) : that.data != null) return false;
        return timestamp != null ? timestamp.equals(that.timestamp) : that.timestamp == null;
    }

    @Override
    public int hashCode() {
        int result = (success ? 1 : 0);
        result = 31 * result + (message != null ? message.hashCode() : 0);
        result = 31 * result + (data != null ? data.hashCode() : 0);
        result = 31 * result + (timestamp != null ? timestamp.hashCode() : 0);
        return result;
    }
}