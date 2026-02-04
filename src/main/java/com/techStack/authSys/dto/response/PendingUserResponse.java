package com.techStack.authSys.dto.response;

import com.techStack.authSys.dto.internal.RequesterContext;
import com.techStack.authSys.models.user.ApprovalLevel;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import java.time.Instant;
import java.util.Set;

/**
 * Clean, immutable response structures
 */
@Data
@Builder
@Jacksonized
public class PendingUserResponse {
    @NotBlank
    private String id;

    @Email
    private String email;

    @NotBlank
    private String firstName;

    @NotBlank
    private String lastName;

    @NotEmpty
    private Set<Roles> roles;

    @NotNull
    private UserStatus status;

    @NotNull
    private ApprovalLevel approvalLevel;

    @NotNull
    private Instant createdAt;

    private String department;

    private boolean canApprove;

    @NotNull
    private RequesterContext requesterContext;
}

