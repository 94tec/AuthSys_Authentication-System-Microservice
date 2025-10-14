package com.techStack.authSys.models;

import com.google.cloud.spring.data.firestore.Document;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collectionName = "users_permissions")
public class UserPermissions {
    private String userId;
    private String email;
    private User.Status status;
    private Instant approvedAt;
    private String approvedBy;

    // Firestore requires Lists (not Sets) and serializable elements
    private List<String> roles;
    private List<String> permissions;
}
