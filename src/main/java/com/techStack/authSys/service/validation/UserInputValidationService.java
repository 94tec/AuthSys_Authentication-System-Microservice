package com.techStack.authSys.service.validation;

import com.techStack.authSys.constants.SecurityConstants;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.service.CustomException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

/**
 * User Input Validation Service
 *
 * Centralized validation using SecurityConstants
 */
@Slf4j
@Service
public class UserInputValidationService {

    /* =========================
       Master Validation Method
       ========================= */

    public Mono<UserRegistrationDTO> validateUserInput(UserRegistrationDTO userDto) {
        return Mono.defer(() -> {
            if (userDto == null) {
                return Mono.error(createValidationError(
                        "Invalid request payload",
                        SecurityConstants.FIELD_PAYLOAD,
                        SecurityConstants.ERROR_REQUEST_INVALID
                ));
            }

            return validateEmail(userDto.getEmail())
                    .then(validatePassword(userDto.getPassword()))
                    .then(validateFirstName(userDto.getFirstName()))
                    .then(validateLastName(userDto.getLastName()))
                    .then(validateIdentityNo(userDto.getIdentityNo()))
                    .then(validatePhoneNumber(userDto.getPhoneNumber()))
                    .thenReturn(userDto);
        });
    }

    /* =========================
       Individual Validations
       ========================= */

    private Mono<Void> validateEmail(String email) {
        if (!StringUtils.hasText(email)) {
            return Mono.error(createValidationError(
                    "Email is required",
                    SecurityConstants.FIELD_EMAIL,
                    SecurityConstants.ERROR_EMAIL_REQUIRED
            ));
        }

        if (!SecurityConstants.EMAIL_PATTERN.matcher(email).matches()) {
            return Mono.error(createValidationError(
                    "Invalid email format",
                    SecurityConstants.FIELD_EMAIL,
                    SecurityConstants.ERROR_EMAIL_INVALID
            ));
        }

        return Mono.empty();
    }

    private Mono<Void> validatePassword(String password) {
        if (!StringUtils.hasText(password)) {
            return Mono.error(createValidationError(
                    "Password is required",
                    SecurityConstants.FIELD_PASSWORD,
                    SecurityConstants.ERROR_PASSWORD_REQUIRED
            ));
        }

        if (!SecurityConstants.STRONG_PASSWORD_PATTERN.matcher(password).matches()) {
            return Mono.error(createValidationError(
                    "Password does not meet strength requirements",
                    SecurityConstants.FIELD_PASSWORD,
                    SecurityConstants.ERROR_PASSWORD_WEAK
            ));
        }

        return Mono.empty();
    }

    private Mono<Void> validateFirstName(String firstName) {
        if (!StringUtils.hasText(firstName) || firstName.trim().length() < 2) {
            return Mono.error(createValidationError(
                    "First name must be at least 2 characters",
                    SecurityConstants.FIELD_FIRST_NAME,
                    SecurityConstants.ERROR_FIRSTNAME_REQUIRED
            ));
        }

        return Mono.empty();
    }

    private Mono<Void> validateLastName(String lastName) {
        if (!StringUtils.hasText(lastName) || lastName.trim().length() < 2) {
            return Mono.error(createValidationError(
                    "Last name must be at least 2 characters",
                    SecurityConstants.FIELD_LAST_NAME,
                    SecurityConstants.ERROR_LASTNAME_REQUIRED
            ));
        }

        return Mono.empty();
    }

    private Mono<Void> validateIdentityNo(String identityNo) {
        if (!StringUtils.hasText(identityNo)) {
            return Mono.empty(); // Optional
        }

        if (!SecurityConstants.KENYAN_ID_PATTERN.matcher(identityNo).matches()) {
            return Mono.error(createValidationError(
                    "Invalid Kenyan Identity Number format",
                    SecurityConstants.FIELD_IDENTITY_NO,
                    SecurityConstants.ERROR_IDENTITY_NO_INVALID
            ));
        }

        return Mono.empty();
    }

    private Mono<Void> validatePhoneNumber(String phoneNumber) {
        if (!StringUtils.hasText(phoneNumber)) {
            return Mono.empty(); // Optional
        }

        if (!SecurityConstants.KENYAN_PHONE_PATTERN.matcher(phoneNumber).matches()) {
            return Mono.error(createValidationError(
                    "Invalid Kenyan phone number format",
                    SecurityConstants.FIELD_PHONE_NUMBER,
                    SecurityConstants.ERROR_PHONE_NUMBER_INVALID
            ));
        }

        return Mono.empty();
    }

    /* =========================
       Error Builder
       ========================= */

    private CustomException createValidationError(
            String message,
            String field,
            String errorCode
    ) {
        log.warn("Validation failed [{}]: {}", field, message);

        return new CustomException(
                HttpStatus.BAD_REQUEST,
                message,
                field,
                errorCode
        );
    }
}
