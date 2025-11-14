package com.techStack.authSys.dto;

import com.techStack.authSys.models.Roles;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import java.time.Instant;

@Data
@Builder
@Jacksonized
public class SecurityContext {
    @NotBlank
    private String requesterEmail;

    @NotNull
    private Roles requesterRole;

    @NotNull
    private Instant authenticationTime;
}