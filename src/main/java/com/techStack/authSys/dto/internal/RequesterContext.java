package com.techStack.authSys.dto.internal;

import com.techStack.authSys.models.user.Roles;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import java.time.Instant;

@Data
@Builder
@Jacksonized
public class RequesterContext {
    @NotBlank
    private String requesterEmail;

    @NotNull
    private Roles requesterRole;

    @NotNull
    private Instant timestamp;
}
