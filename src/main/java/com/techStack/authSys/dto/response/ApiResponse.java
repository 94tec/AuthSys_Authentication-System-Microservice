package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Enhanced Standardized API Response Wrapper
 *
 * Provides consistent response structure across all API endpoints with:
 * - Error codes for programmatic handling
 * - Metadata for additional context
 * - Validation error details
 * - Timestamp tracking (Clock-compatible)
 * - Swagger/OpenAPI annotations
 *
 * @param <T> Type of the data in success response
 */
@Setter
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Standard API response wrapper")
public class ApiResponse<T> implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /* =========================
       Core Response Fields
       ========================= */

    @Schema(description = "Indicates if the request was successful", example = "true")
    private boolean success;

    @Schema(description = "Human-readable message describing the result",
            example = "Login successful")
    private String message;

    @Schema(description = "Response data payload")
    private T data;

    @Schema(description = "Timestamp of the response (ISO-8601)",
            example = "2026-02-13T10:30:00Z")
    private Instant timestamp;

    @Schema(description = "Timestamp in milliseconds since epoch",
            example = "1707822600000")
    private Long timestampMillis;

    /* =========================
       Error Handling Fields
       ========================= */

    @Schema(description = "Error code for programmatic handling",
            example = "INVALID_CREDENTIALS")
    private String errorCode;

    @Schema(description = "Validation errors (field -> error message)")
    private Map<String, String> validationErrors;

    @Schema(description = "Additional metadata")
    private Map<String, Object> metadata;

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
     * Constructor with error code
     */
    public ApiResponse(boolean success, String message, T data, String errorCode) {
        this.success = success;
        this.message = message;
        this.data = data;
        this.errorCode = errorCode;
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
     * ✅ FIXED: now generic
     */
    public static <T> ApiResponse<T> success(String message) {
        return new ApiResponse<>(true, message, null);
    }

    /**
     * Success with message and explicit timestamp
     * ✅ FIXED: now generic
     */
    public static <T> ApiResponse<T> success(String message, Instant timestamp) {
        return new ApiResponse<>(true, message, null, timestamp);
    }

    /**
     * Default success with no data or message
     * ✅ FIXED: now generic
     */
    public static <T> ApiResponse<T> success() {
        return new ApiResponse<>(true, "Operation successful", null);
    }

    /* =========================
       Error Factory Methods
       ========================= */

    /**
     * Error response with message only
     * ✅ FIXED: now generic
     */
    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(false, message, null);
    }

    /**
     * Error response with message and error code
     * ✅ FIXED: now generic
     */
    public static <T> ApiResponse<T> error(String message, String errorCode) {
        return new ApiResponse<>(false, message, null, errorCode);
    }

    /**
     * Error response with explicit timestamp
     * ✅ FIXED: now generic
     */
    public static <T> ApiResponse<T> error(String message, Instant timestamp) {
        return new ApiResponse<>(false, message, null, timestamp);
    }

    /**
     * Error response with data (e.g., validation errors)
     */
    public static <T> ApiResponse<T> error(String message, T data) {
        return new ApiResponse<>(false, message, data);
    }

    /**
     * Error response with data and error code
     */
    public static <T> ApiResponse<T> error(String message, T data, String errorCode) {
        return new ApiResponse<>(false, message, data, errorCode);
    }

    /**
     * Error response with data and explicit timestamp
     */
    public static <T> ApiResponse<T> error(String message, T data, Instant timestamp) {
        return new ApiResponse<>(false, message, data, timestamp);
    }

    /* =========================
       Validation Error Methods
       ========================= */

    /**
     * Validation error response
     * ✅ FIXED: now generic so it can match ApiResponse<String>, ApiResponse<User>, etc.
     */
    public static <T> ApiResponse<T> validationError(String message, Map<String, String> errors) {
        ApiResponse<T> response = new ApiResponse<>(false, message, null, "VALIDATION_ERROR");
        response.setValidationErrors(errors);
        return response;
    }

    /**
     * Add validation error
     */
    public ApiResponse<T> addValidationError(String field, String error) {
        if (this.validationErrors == null) {
            this.validationErrors = new HashMap<>();
        }
        this.validationErrors.put(field, error);
        return this;
    }

    /* =========================
       Metadata Methods
       ========================= */

    /**
     * Add metadata entry
     */
    public ApiResponse<T> addMetadata(String key, Object value) {
        if (this.metadata == null) {
            this.metadata = new HashMap<>();
        }
        this.metadata.put(key, value);
        return this;
    }

    /**
     * Add multiple metadata entries
     */
    public ApiResponse<T> addMetadata(Map<String, Object> entries) {
        if (this.metadata == null) {
            this.metadata = new HashMap<>();
        }
        this.metadata.putAll(entries);
        return this;
    }

    /* =========================
       Builder Pattern Support
       ========================= */

    /**
     * Set error code (builder style)
     */
    public ApiResponse<T> withErrorCode(String errorCode) {
        this.errorCode = errorCode;
        return this;
    }

    /**
     * Set validation errors (builder style)
     */
    public ApiResponse<T> withValidationErrors(Map<String, String> errors) {
        this.validationErrors = errors;
        return this;
    }

    /**
     * Set metadata (builder style)
     */
    public ApiResponse<T> withMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
        return this;
    }

    /* =========================
       Utility Methods
       ========================= */

    public boolean isSuccess() {
        return success;
    }

    public boolean isError() {
        return !success;
    }

    public boolean hasValidationErrors() {
        return validationErrors != null && !validationErrors.isEmpty();
    }

    public boolean hasMetadata() {
        return metadata != null && !metadata.isEmpty();
    }

    public long getTimestampMillis() {
        return timestampMillis != null ? timestampMillis :
                (timestamp != null ? timestamp.toEpochMilli() : 0L);
    }

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
                ", errorCode='" + errorCode + '\'' +
                ", validationErrors=" + validationErrors +
                ", metadata=" + metadata +
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
        if (message != null ? !message.equals(that.message) : that.message != null) return false;
        if (data != null ? !data.equals(that.data) : that.data != null) return false;
        if (errorCode != null ? !errorCode.equals(that.errorCode) : that.errorCode != null)
            return false;
        return timestamp != null ? timestamp.equals(that.timestamp) : that.timestamp == null;
    }

    @Override
    public int hashCode() {
        int result = (success ? 1 : 0);
        result = 31 * result + (message != null ? message.hashCode() : 0);
        result = 31 * result + (data != null ? data.hashCode() : 0);
        result = 31 * result + (errorCode != null ? errorCode.hashCode() : 0);
        result = 31 * result + (timestamp != null ? timestamp.hashCode() : 0);
        return result;
    }
}
