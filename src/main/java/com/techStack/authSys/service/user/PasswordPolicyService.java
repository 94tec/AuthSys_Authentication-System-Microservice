package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.exception.service.CustomException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class PasswordPolicyService {

    private static final Logger logger = LoggerFactory.getLogger(PasswordPolicyService.class);

    private final PasswordHistoryService passwordHistoryService;

    public Mono<UserDTO> validatePassword(UserDTO userDto) {
        String password = userDto.getPassword();

        // Local validations
        if (password == null || password.length() < 8) {
            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Password must be at least 8 characters long"));
        }
        if (!password.matches(".*[A-Z].*")) {
            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Password must contain at least one uppercase letter"));
        }
        if (!password.matches(".*[\\W_].*")) {
            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Password must contain at least one special character"));
        }

        // Password history check
        if (userDto.getUid() != null) {
            return passwordHistoryService.isPasswordReused(userDto.getUid(), password)
                    .flatMap(reused -> {
                        if (reused) {
                            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Password cannot be the same as one of your last 5 passwords"));
                        }
                        return Mono.just(userDto);
                    });
        }

        return Mono.just(userDto);
    }
}
