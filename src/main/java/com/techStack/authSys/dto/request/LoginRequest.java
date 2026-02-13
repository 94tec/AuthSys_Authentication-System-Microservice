package com.techStack.authSys.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Login Request DTO
 *
 * Standard login credentials.
 */

public record LoginRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        String password
) {
    // Getter methods for compatibility with some frameworks
    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}