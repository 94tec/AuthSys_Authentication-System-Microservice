package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.io.Serializable;

/**
 * Standardized API response wrapper
 *
 * @param <T> Type of the data in success response
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> implements Serializable {

    private static final long serialVersionUID = 1L;

    private boolean success;
    private String message;
    private T data;
    private long timestamp;

    // ===== Constructors =====
    public ApiResponse() {
        this.timestamp = System.currentTimeMillis();
    }

    public ApiResponse(boolean success, String message, T data) {
        this.success = success;
        this.message = message;
        this.data = data;
        this.timestamp = System.currentTimeMillis();
    }

    // ===== Success Factory Methods =====

    /** Success with typed data */
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, "Operation successful", data);
    }

    /** Success with typed data and custom message */
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }

    /** Success with message but no data */
    public static ApiResponse<Void> success(String message) {
        return new ApiResponse<>(true, message, null);
    }

    /** Default success with no data or message */
    public static ApiResponse<Void> success() {
        return new ApiResponse<>(true, "Operation successful", null);
    }

    // ===== Error Factory Methods =====

    /** Error response (no generics, safe for all paths) */
    public static ApiResponse<Void> error(String message) {
        return new ApiResponse<>(false, message, null);
    }

    // ===== Getters & Setters =====

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public T getData() { return data; }
    public void setData(T data) { this.data = data; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    @Override
    public String toString() {
        return "ApiResponse{" +
                "success=" + success +
                ", message='" + message + '\'' +
                ", data=" + data +
                ", timestamp=" + timestamp +
                '}';
    }
}
