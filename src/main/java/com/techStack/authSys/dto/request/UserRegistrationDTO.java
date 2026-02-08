package com.techStack.authSys.dto.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.cloud.firestore.annotation.PropertyName;
import com.techStack.authSys.models.user.Roles;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * User Registration Request DTO
 *
 * Used exclusively for new user registration requests.
 * Contains only the fields needed for registration.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationDTO {
    @JsonIgnore
    private String uid;

    /* =========================
       Required Fields
       ========================= */

    @NotBlank(message = "Email cannot be blank")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "First name cannot be blank")
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    private String firstName;

    @NotBlank(message = "Last name cannot be blank")
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    private String lastName;

    @NotBlank(message = "Password cannot be blank")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "Password must contain uppercase, lowercase, number, and special character"
    )
    private String password;

    /* =========================
       Optional Fields
       ========================= */

    @Pattern(regexp = "\\d{8}", message = "Invalid Kenyan Identity Number format")
    private String identityNo;

    @Pattern(regexp = "\\+254[17]\\d{8}", message = "Invalid Kenyan phone number format")
    private String phoneNumber;


    @PropertyName("requested_role")
    private String requestedRole;

    @PropertyName("requested_roles")
    private Set<String> requestedRoles;
    private String department;

    private String userAgent;

    public Set<Roles> getRequestedRoleEnums() {
        if (requestedRoles == null || requestedRoles.isEmpty()) {
            return Set.of(Roles.USER); // default role
        }

        return requestedRoles.stream()
                .map(String::toUpperCase)
                .map(Roles::valueOf)
                .collect(Collectors.toSet());
    }

    /* =========================
       Registration Metadata
       ========================= */

    private RegistrationMetadata metadata;

    /**
     * Registration Metadata
     * Contains context about the registration attempt
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RegistrationMetadata {
        private String honeypot;        // Bot detection field (should be empty)
        private String userAgent;       // Browser/device info
        private String referrer;        // Where user came from
        private String deviceFingerprint; // Device identification
    }
}
