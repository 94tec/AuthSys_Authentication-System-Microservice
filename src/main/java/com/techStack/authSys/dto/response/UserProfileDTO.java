package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.techStack.authSys.models.user.User;
import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * User Profile DTO
 *
 * Used for displaying user profiles.
 * Contains both User and UserProfile information.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserProfileDTO {

    /* =========================
       Basic Profile Info
       ========================= */

    private String id;
    private String userId;  // Reference to User entity
    private String firstName;
    private String lastName;
    private String username;
    private String email;  // Optional, only if public
    private String profilePictureUrl;
    private String bio;

    /* =========================
       Additional Info
       ========================= */

    private String department;
    private String phoneNumber;  // Optional, only if public
    private boolean isPublic;

    /* =========================
       Roles (Public)
       ========================= */

    private List<String> roles;

    /* =========================
       Audit
       ========================= */

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant createdAt;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant updatedAt;

    /* =========================
       Conversion Methods
       ========================= */

    /**
     * Create UserProfileDTO from User entity.
     *
     * @param user the user entity
     * @param includePrivateInfo whether to include email and phone
     */
    public static UserProfileDTO fromEntity(User user, boolean includePrivateInfo) {
        if (user == null) {
            return null;
        }

        UserProfileDTOBuilder builder = UserProfileDTO.builder()
                .id(user.getUserProfileId())
                .userId(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .profilePictureUrl(user.getProfilePictureUrl())
                .bio(user.getBio())
                .department(user.getDepartment())
                .roles(user.getRoleNames())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt());

        if (includePrivateInfo) {
            builder
                    .email(user.getEmail())
                    .phoneNumber(user.getPhoneNumber());
        }

        return builder.build();
    }

    /**
     * Create public profile (no private information).
     */
    public static UserProfileDTO fromEntityPublic(User user) {
        return fromEntity(user, false);
    }

    /**
     * Create full profile (includes private information).
     */
    public static UserProfileDTO fromEntityFull(User user) {
        return fromEntity(user, true);
    }

    /**
     * Get full name.
     */
    public String getFullName() {
        if (firstName == null && lastName == null) {
            return username;
        }
        return String.format("%s %s",
                firstName != null ? firstName : "",
                lastName != null ? lastName : ""
        ).trim();
    }

    /**
     * Convert list of users to profile DTOs.
     */
    public static List<UserProfileDTO> fromEntityList(List<User> users, boolean includePrivateInfo) {
        return users.stream()
                .map(user -> fromEntity(user, includePrivateInfo))
                .collect(Collectors.toList());
    }
}