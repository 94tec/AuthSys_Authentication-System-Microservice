package com.techStack.authSys.dto.response;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * User Update Request DTO
 *
 * Used for updating user profile information.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserUpdateDTO {

    @Email(message = "Invalid email format")
    private String email;

    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    private String firstName;

    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    private String lastName;

    @Pattern(regexp = "\\d{8}", message = "Invalid Kenyan Identity Number format")
    private String identityNo;

    @Pattern(regexp = "\\+254[17]\\d{8}", message = "Invalid Kenyan phone number format")
    private String phoneNumber;

    @Size(max = 500, message = "Bio must be less than 500 characters")
    private String bio;

    private String profilePictureUrl;
    private String department;
}
