package com.techStack.authSys.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {

    private String uid; // Firebase UID instead of DB ID

    @NotBlank(message = "First Name cannot be blank")
    private String firstName;

    @NotBlank(message = "Last Name cannot be blank")
    private String lastName;

    @NotBlank(message = "Email cannot be blank")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Username cannot be blank")
    private String username;

    @NotBlank(message = "password field cannot be blank")
    private String password;

    @NotBlank(message = "Identity Number cannot be blank")
    @Pattern(regexp = "\\d{8}", message = "Invalid Kenyan Identity Number format")
    private String identityNo;

    @NotBlank(message = "Phone number cannot be blank")
    @Pattern(regexp = "\\+254[17]\\d{8}", message = "Invalid Kenyan phone number format")
    private String phoneNumber;

    private List<String> roles;
    private String honeypot;
    private RegistrationMetadata registrationMetadata;
    private String userAgent;
    private boolean forcePasswordChange;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RegistrationMetadata {
        private String honeypot; // Field to detect bot/spam registrations
        private String userAgent; // Browser/Device info
        private String referrer; // Where the user came from

        public RegistrationMetadata(String id, String ipAddress, Instant now, String deviceFingerprint) {
        }
    }
}
