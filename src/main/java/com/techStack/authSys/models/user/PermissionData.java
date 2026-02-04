package com.techStack.authSys.models.user;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

/**
 * Data class representing permission information for a user
 */
@Data
@Builder
public class PermissionData {
    private List<String> roles;
    private List<String> permissions;
    private UserStatus status;
    private String approvedBy;
    private Instant approvedAt;
}