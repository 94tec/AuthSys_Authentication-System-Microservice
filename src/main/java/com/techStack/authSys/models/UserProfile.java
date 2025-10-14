package com.techStack.authSys.models;

import com.google.cloud.firestore.annotation.DocumentId;
import com.google.cloud.spring.data.firestore.Document;
import lombok.*;
import org.springframework.data.annotation.Id;

import java.util.List;
import java.util.Set;
import java.util.UUID;

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
    private boolean isPublic;

    private List<String> roles;
    private List<String> permissions;
    public User user;

}
