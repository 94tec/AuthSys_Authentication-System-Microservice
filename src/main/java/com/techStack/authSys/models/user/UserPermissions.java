package com.techStack.authSys.models.user;

import com.google.cloud.spring.data.firestore.Document;
import com.techStack.authSys.models.authorization.Permissions;
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
    private List<Roles> roles;
    private List<Permissions> permissions;
    private UserStatus status; // ACTIVE, PENDING_APPROVAL, REJECTED
    private String approvedBy; // Manager/Admin who approved
    private Instant approvedAt;
    private Instant createdAt;
    private String rejectionReason; // If rejected
}
