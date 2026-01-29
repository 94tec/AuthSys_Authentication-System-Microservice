package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.registration.UserRegistrationOrchestrator;
import com.techStack.authSys.service.verification.EmailVerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Facade for authentication operations.
 * Delegates to specialized services for each operation.
 *
 * This class now has a single responsibility: routing requests
 * to the appropriate specialized service.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRegistrationOrchestrator registrationService;
    private final EmailVerificationService verificationService;

    /**
     * Registers a new user account.
     *
     * @param userDto  User registration data
     * @param exchange HTTP exchange containing request metadata
     * @return Newly created user
     */
    public Mono<User> registerUser(UserDTO userDto, ServerWebExchange exchange) {
        return registrationService.registerUser(userDto, exchange);
    }

    /**
     * Verifies a user's email address using a verification token.
     *
     * @param token     Email verification token
     * @param ipAddress Client IP address for security validation
     * @return Void on success
     */
    public Mono<Void> verifyEmail(String token, String ipAddress) {
        return verificationService.verifyEmail(token, ipAddress);
    }

    /**
     * Resends a verification email to a user.
     *
     * @param email     User's email address
     * @param ipAddress Client IP address
     * @return Void on success
     */
    public Mono<Void> resendVerificationEmail(String email, String ipAddress) {
        return verificationService.resendVerificationEmail(email, ipAddress);
    }
}