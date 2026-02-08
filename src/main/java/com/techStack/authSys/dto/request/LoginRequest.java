package com.techStack.authSys.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login Request DTO
 *
 * Represents the login request payload with validation.
 * Supports standard login, MFA, device recognition, and geolocation context.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    /* =========================
       Required Fields
       ========================= */

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be 8-100 characters")
    private String password;

    /* =========================
       Optional Fields
       ========================= */

    /**
     * User identifier (optional, mainly used for admin operations)
     */
    private String userId;

    /**
     * IP address (usually extracted from request, but can be provided)
     */
    private String ipAddress;

    /**
     * Device fingerprint (usually generated server-side, but can be provided)
     */
    private String deviceFingerprint;

    /* =========================
       MFA Fields
       ========================= */

    /**
     * Multi-factor authentication code (TOTP/SMS)
     */
    private String mfaCode;

    /**
     * MFA method used (e.g., "TOTP", "SMS", "EMAIL")
     */
    private String mfaMethod;

    /* =========================
       Device Recognition Fields
       ========================= */

    /**
     * Human-readable device name (e.g., "John's iPhone")
     */
    private String deviceName;

    /**
     * Device type (e.g., "MOBILE", "DESKTOP", "TABLET")
     */
    private String deviceType;

    /**
     * Device OS (e.g., "iOS 17.2", "Windows 11")
     */
    private String deviceOs;

    /**
     * Browser name and version (e.g., "Chrome 120.0")
     */
    private String browserInfo;

    /* =========================
       Geolocation Fields
       ========================= */

    /**
     * Latitude coordinate for location-based security
     */
    private Double latitude;

    /**
     * Longitude coordinate for location-based security
     */
    private Double longitude;

    /**
     * City/location name (optional, for display purposes)
     */
    private String locationName;

    /* =========================
       Security Challenge Fields
       ========================= */

    /**
     * Security challenge response (for CAPTCHA, security questions, etc.)
     */
    private String challengeResponse;

    /**
     * Challenge type (e.g., "CAPTCHA", "SECURITY_QUESTION")
     */
    private String challengeType;

    /* =========================
       Session Preferences
       ========================= */

    /**
     * Whether to remember this device for future logins
     */
    @Builder.Default
    private boolean rememberDevice = false;

    /**
     * Requested session duration in seconds (optional)
     */
    private Long sessionDuration;

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Check if MFA is provided
     */
    public boolean hasMfaCode() {
        return mfaCode != null && !mfaCode.isBlank();
    }

    /**
     * Check if device fingerprint is provided
     */
    public boolean hasDeviceFingerprint() {
        return deviceFingerprint != null && !deviceFingerprint.isBlank();
    }

    /**
     * Check if geolocation is provided
     */
    public boolean hasGeolocation() {
        return latitude != null && longitude != null;
    }

    /**
     * Check if security challenge is provided
     */
    public boolean hasChallenge() {
        return challengeResponse != null && !challengeResponse.isBlank();
    }

    /**
     * Check if this is a recognized device login
     */
    public boolean isRecognizedDevice() {
        return hasDeviceFingerprint() && (deviceName != null || deviceType != null);
    }

    /**
     * Get display-friendly device description
     */
    public String getDeviceDescription() {
        if (deviceName != null && !deviceName.isBlank()) {
            return deviceName;
        }
        if (deviceType != null && !deviceType.isBlank()) {
            return deviceType + " device";
        }
        return "Unknown device";
    }

    /**
     * Sanitize sensitive data for logging
     */
    public LoginRequest sanitizedCopy() {
        return LoginRequest.builder()
                .email(this.email)
                .userId(this.userId)
                .ipAddress(this.ipAddress)
                .deviceFingerprint(this.deviceFingerprint != null
                        ? this.deviceFingerprint.substring(0, Math.min(8, this.deviceFingerprint.length())) + "..."
                        : null)
                .mfaMethod(this.mfaMethod)
                .deviceName(this.deviceName)
                .deviceType(this.deviceType)
                .deviceOs(this.deviceOs)
                .browserInfo(this.browserInfo)
                .latitude(this.latitude)
                .longitude(this.longitude)
                .locationName(this.locationName)
                .challengeType(this.challengeType)
                .rememberDevice(this.rememberDevice)
                .sessionDuration(this.sessionDuration)
                .build();
    }

    /**
     * Validate geolocation coordinates
     */
    public boolean hasValidGeolocation() {
        if (latitude == null || longitude == null) {
            return false;
        }
        return latitude >= -90 && latitude <= 90 && longitude >= -180 && longitude <= 180;
    }

    /**
     * Get location context for audit logging
     */
    public String getLocationContext() {
        if (locationName != null && !locationName.isBlank()) {
            return locationName;
        }
        if (hasValidGeolocation()) {
            return String.format("%.2f, %.2f", latitude, longitude);
        }
        return "Unknown location";
    }
}