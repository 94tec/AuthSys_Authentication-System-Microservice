package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.exception.service.CustomException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.util.regex.Pattern;

@Slf4j
@Service
public class UserInputValidationService {

    // ===========================
    // EMAIL REGEX
    // ===========================
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$",
            Pattern.CASE_INSENSITIVE
    );

    // ===========================
    // PASSWORD RULES (Optional)
    // ===========================
    private static final Pattern STRONG_PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).{8,}$"
    );

    // ===========================
    // FIELD CONSTANTS
    // ===========================
    private static final String FIELD_EMAIL = "email";
    private static final String FIELD_PASSWORD = "password";
    private static final String FIELD_FIRST_NAME = "firstName";
    private static final String FIELD_LAST_NAME = "lastName";
    private static final String FIELD_PAYLOAD = "payload";

    // ===========================
    // ERROR CODE CONSTANTS
    // ===========================
    private static final String ERROR_REQUEST_INVALID = "REQUEST_INVALID";
    private static final String ERROR_EMAIL_REQUIRED = "EMAIL_REQUIRED";
    private static final String ERROR_EMAIL_INVALID = "EMAIL_INVALID";
    private static final String ERROR_PASSWORD_REQUIRED = "PASSWORD_REQUIRED";
    private static final String ERROR_PASSWORD_WEAK = "PASSWORD_WEAK";
    private static final String ERROR_FIRSTNAME_REQUIRED = "FIRSTNAME_REQUIRED";
    private static final String ERROR_LASTNAME_REQUIRED = "LASTNAME_REQUIRED";

    // ===========================
    // MASTER VALIDATION METHOD
    // ===========================
    public Mono<UserDTO> validateUserInput(UserDTO userDto) {
        return Mono.defer(() -> {

            if (userDto == null) {
                return Mono.error(createValidationError(
                        "Invalid request payload", FIELD_PAYLOAD, ERROR_REQUEST_INVALID));
            }

            return validateEmail(userDto.getEmail())
                    .then(validatePassword(userDto.getPassword()))
                    .then(validateFirstName(userDto.getFirstName()))
                    .then(validateLastName(userDto.getLastName()))
                    .thenReturn(userDto);
        });
    }

    // ===========================
    // EMAIL VALIDATION
    // ===========================
    private Mono<Void> validateEmail(String email) {

        if (!StringUtils.hasText(email)) {
            return Mono.error(createValidationError(
                    "Email is required", FIELD_EMAIL, ERROR_EMAIL_REQUIRED));
        }

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return Mono.error(createValidationError(
                    "Invalid email format", FIELD_EMAIL, ERROR_EMAIL_INVALID));
        }

        return Mono.empty();
    }

    // ===========================
    // PASSWORD VALIDATION
    // ===========================
    private Mono<Void> validatePassword(String password) {
        if (!StringUtils.hasText(password)) {
            return Mono.error(createValidationError(
                    "Password is required", FIELD_PASSWORD, ERROR_PASSWORD_REQUIRED));
        }

        // OPTIONAL: enforce strong password
        if (!STRONG_PASSWORD_PATTERN.matcher(password).matches()) {
            return Mono.error(createValidationError(
                    "Password must be at least 8 chars, contain lowercase, uppercase, and number",
                    FIELD_PASSWORD,
                    ERROR_PASSWORD_WEAK
            ));
        }


        return Mono.empty();
    }

    // ===========================
    // FIRST NAME VALIDATION
    // ===========================
    private Mono<Void> validateFirstName(String firstName) {
        if (!StringUtils.hasText(firstName)) {
            return Mono.error(createValidationError(
                    "First name is required", FIELD_FIRST_NAME, ERROR_FIRSTNAME_REQUIRED));
        }
        return Mono.empty();
    }

    // ===========================
    // LAST NAME VALIDATION
    // ===========================
    private Mono<Void> validateLastName(String lastName) {
        if (!StringUtils.hasText(lastName)) {
            return Mono.error(createValidationError(
                    "Last name is required", FIELD_LAST_NAME, ERROR_LASTNAME_REQUIRED));
        }
        return Mono.empty();
    }

    // ===========================
    // BUILD ERROR RESPONSE
    // ===========================
    private CustomException createValidationError(String message, String field, String errorCode) {
        return new CustomException(
                HttpStatus.BAD_REQUEST,
                message,
                field,
                errorCode
        );
    }
}

