package com.techStack.authSys.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ForcePasswordChangeRequest {
    @NotBlank
    private String userId;

    @NotBlank
    @Size(min = 8)
    private String newPassword;
}
