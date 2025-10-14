package com.techStack.authSys.dto;

import java.util.List;

public class UserPermissionsDTO {
    private String userId;
    private List<String> roles;
    private List<String> permissions;

    public UserPermissionsDTO(String userId, List<String> roles, List<String> permissions) {
        this.userId = userId;
        this.roles = roles;
        this.permissions = permissions;
    }

    // Getters and setters
}

