package com.techStack.authSys.dto.response;

import com.techStack.authSys.models.user.UserProfile;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserProfileDTO {
    private String id;
    private String firstName;
    private String lastName;
    private String profilePictureUrl;
    private String bio;
    private boolean isPublic;
    private String userId;

    public static UserProfileDTO fromEntity(UserProfile profile) {
        return UserProfileDTO.builder()
                .id(profile.getId())
                .firstName(profile.getFirstName())
                .lastName(profile.getLastName())
                .profilePictureUrl(profile.getProfilePictureUrl())
                .bio(profile.getBio())
                .isPublic(profile.isPublic())
                .userId(profile.getUserId())
                .build();
    }
}