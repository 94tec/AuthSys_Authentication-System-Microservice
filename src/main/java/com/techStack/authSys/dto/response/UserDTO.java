package com.techStack.authSys.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.models.user.ApprovalLevel;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * User Data Transfer Object
 *
 * Used for API responses and requests.
 * Separates internal domain model from external API contract.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDTO {

    /* =========================
       Core Identity
       ========================= */

    private String id;  // Firebase UID

    @NotBlank(message = "Email cannot be blank")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "First name cannot be blank")
    private String firstName;

    @NotBlank(message = "Last name cannot be blank")
    private String lastName;

    private String username;

    @Pattern(regexp = "\\d{8}", message = "Invalid Kenyan Identity Number format")
    private String identityNo;

    @Pattern(regexp = "\\+254[17]\\d{8}", message = "Invalid Kenyan phone number format")
    private String phoneNumber;

    /* =========================
       Roles & Permissions
       ========================= */

    private List<String> roles;
    private List<String> permissions;
    private String requestedRole;
    private String department;

    /* =========================
       Account Status
       ========================= */

    private UserStatus status;
    private ApprovalLevel approvalLevel;
    private boolean enabled;
    private boolean accountLocked;
    private boolean emailVerified;
    private boolean mfaEnabled;
    private boolean mfaRequired;
    private boolean forcePasswordChange;

    /* =========================
       Profile Information
       ========================= */

    private String profilePictureUrl;
    private String bio;

    /* =========================
       Security Information (Limited)
       ========================= */

    private Integer failedLoginAttempts;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant lastLogin;

    private String lastLoginIp;

    /* =========================
       Approval Workflow
       ========================= */

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant approvedAt;

    private String approvedBy;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant rejectedAt;

    private String rejectedBy;
    private String rejectionReason;

    /* =========================
       Audit Information
       ========================= */

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant createdAt;

    private String createdBy;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX", timezone = "UTC")
    private Instant updatedAt;

    /* =========================
       Custom Attributes (ABAC)
       ========================= */

    private Map<String, Object> attributes;

    /* =========================
       Conversion Methods
       ========================= */

    /**
     * Create UserDTO from User entity.
     * Default conversion includes basic information.
     */
    public static UserDTO fromEntity(User user) {
        return fromEntity(user, false);
    }

    /**
     * Create UserDTO from User entity with optional detailed information.
     *
     * @param user the user entity
     * @param includeDetails whether to include security and approval details
     */
    public static UserDTO fromEntity(User user, boolean includeDetails) {
        if (user == null) {
            return null;
        }

        UserDTOBuilder builder = UserDTO.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .identityNo(user.getIdentityNo())
                .phoneNumber(user.getPhoneNumber())
                .roles(user.getRoleNames())
                .permissions(user.getAdditionalPermissions())
                .requestedRole(user.getRequestedRoles() != null ? user.getRequestedRoles().name() : null)
                .department(user.getDepartment())
                .status(user.getStatus())
                .approvalLevel(user.getApprovalLevel())
                .enabled(user.isEnabled())
                .accountLocked(user.isAccountLocked())
                .emailVerified(user.isEmailVerified())
                .mfaEnabled(user.isMfaEnabled())
                .mfaRequired(user.isMfaRequired())
                .forcePasswordChange(user.isForcePasswordChange())
                .profilePictureUrl(user.getProfilePictureUrl())
                .bio(user.getBio())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt());

        // Include detailed information if requested
        if (includeDetails) {
            builder
                    .failedLoginAttempts(user.getFailedLoginAttempts())
                    .lastLogin(user.getLastLogin())
                    .lastLoginIp(user.getLastLoginIp())
                    .approvedAt(user.getApprovedAt())
                    .approvedBy(user.getApprovedBy())
                    .rejectedAt(user.getRejectedAt())
                    .rejectedBy(user.getRejectedBy())
                    .rejectionReason(user.getRejectionReason())
                    .createdBy(user.getCreatedBy())
                    .attributes(user.getAttributes());
        }

        return builder.build();
    }

    /**
     * Create minimal UserDTO with only essential public information.
     * Used for public profiles or user lists.
     */
    public static UserDTO fromEntityMinimal(User user) {
        if (user == null) {
            return null;
        }

        return UserDTO.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .profilePictureUrl(user.getProfilePictureUrl())
                .bio(user.getBio())
                .build();
    }

    /**
     * Convert list of User entities to UserDTOs.
     */
    public static List<UserDTO> fromEntityList(List<User> users) {
        return users.stream()
                .map(UserDTO::fromEntity)
                .collect(Collectors.toList());
    }

    /**
     * Convert list of User entities to minimal UserDTOs.
     */
    public static List<UserDTO> fromEntityListMinimal(List<User> users) {
        return users.stream()
                .map(UserDTO::fromEntityMinimal)
                .collect(Collectors.toList());
    }
}