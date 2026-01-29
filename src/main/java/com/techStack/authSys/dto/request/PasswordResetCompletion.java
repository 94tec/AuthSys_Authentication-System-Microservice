package com.techStack.authSys.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PasswordResetCompletion {
    @NotBlank(message = "Token is required")
    private String token;

    @NotBlank(message = "New password is required")
    private String newPassword;
}
