package com.techStack.authSys.dto.request;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Bootstrap Request DTO
 *
 * Used for creating initial Super Admin via bootstrap endpoint.
 */
public record BootstrapRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "Phone number is required")
        @Pattern(
                regexp = "^\\+[1-9]\\d{1,14}$",
                message = "Phone must be in E.164 format (e.g., +254712345678)"
        )
        String phone
) {}
