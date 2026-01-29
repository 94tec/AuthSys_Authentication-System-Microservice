package com.techStack.authSys.dto.internal;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class TokenValidationRequest {
    @NotBlank(message = "Token is required")
    private String token;
}
