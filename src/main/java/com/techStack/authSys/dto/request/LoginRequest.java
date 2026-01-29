package com.techStack.authSys.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Represents the login request payload
 */
@Data
public class LoginRequest {

    private String userId;
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be 8-100 characters")
    private String password;

    @NotBlank(message = "IP address is required")
    private String ipAddress;

    @NotBlank(message = "Device fingerprint is required")
    private String deviceFingerprint;

    // For MFA cases
    private String mfaCode;

    // For device recognition
    private String deviceName;
    private String deviceType;

    // For geolocation context
    private Double latitude;
    private Double longitude;

    // For security challenge requests
    private String challengeResponse;

}
