package com.techStack.authSys.dto;

import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.RoleAssignmentService;
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
    private User.Status status;

    @NotNull
    private RoleAssignmentService.ApprovalLevel approvalLevel;

    @NotNull
    private Instant createdAt;

    private String department;

    private boolean canApprove;

    @NotNull
    private RequesterContext requesterContext;
}

