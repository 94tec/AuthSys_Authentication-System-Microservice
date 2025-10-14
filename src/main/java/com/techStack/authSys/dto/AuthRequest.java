package com.techStack.authSys.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.Objects;

@Getter
@Builder
@ToString(exclude = "password") // Prevent logging the password
public class AuthRequest {

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private final String email;

    @NotBlank(message = "Password is required")
    private final String password;

    @NotBlank(message = "IP address is required")
    private final String ipAddress;

    @NotBlank(message = "Device fingerprint is required")
    private final String deviceFingerprint;

    @NotBlank(message = "User agent is required")
    private final String userAgent;

    @JsonCreator
    public AuthRequest(
            @JsonProperty("email") String email,
            @JsonProperty("password") String password,
            @JsonProperty("ipAddress") String ipAddress,
            @JsonProperty("deviceFingerprint") String deviceFingerprint,
            @JsonProperty("userAgent") String userAgent) {
        this.email = Objects.requireNonNull(email);
        this.password = Objects.requireNonNull(password);
        this.ipAddress = Objects.requireNonNull(ipAddress);
        this.deviceFingerprint = Objects.requireNonNull(deviceFingerprint);
        this.userAgent = Objects.requireNonNull(userAgent);
    }
}
