package com.techStack.authSys.models.user;

import com.google.cloud.firestore.annotation.DocumentId;
import com.google.cloud.spring.data.firestore.Document;
import lombok.*;

import java.time.Instant;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collectionName = "user_profiles")
public class UserProfile {

    @DocumentId
    private String id;

    private String userId;
    private String firstName;
    private String lastName;
    private String profilePictureUrl;
    private String bio;

    // renamed for clarity
    //private boolean publicProfile;
    private boolean isPublic;

    private List<String> roles;
    private List<String> permissions;

    // timestamps for auditing
    private Instant createdAt;
    private Instant updatedAt;

    // optional embedded user reference (if needed)
    private User user;

}
