package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.auth.InvalidTokenException;
import com.techStack.authSys.exception.auth.TokenGenerationException;
import com.techStack.authSys.exception.auth.TokenInvalidationException;
import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.exception.password.PasswordUpdateException;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.notification.EmailServiceInstance1;
import com.techStack.authSys.service.security.DomainValidationService;
import com.techStack.authSys.service.token.PasswordResetTokenService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private static final Logger logger = LoggerFactory.getLogger(PasswordResetService.class);
    private static final int MAX_RETRIES = 3;
    private static final Duration RETRY_DELAY = Duration.ofMillis(500);

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PasswordEncoder passwordEncoder;
    private final EmailServiceInstance1 emailService;
    private final PasswordResetTokenService tokenService;
    private final PasswordPolicyService passwordPolicyService;
    private final DomainValidationService domainValidationService;

    public Mono<String> initiatePasswordReset(String email) {
        return validateEmail(email)
                .flatMap(this::findUserByEmail)
                .flatMap(user -> generateAndStoreToken(user.getEmail()))
                .flatMap(token -> sendResetEmail(email, token))
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(this::isRecoverableError)
                )
                .doOnSuccess(__ -> logger.info("Password reset initiated for email: {}", email))
                .doOnError(e -> logger.error("Failed to initiate password reset for email: {}", email, e));
    }

    private Mono<String> validateEmail(String email) {
        return Mono.just(email)
                .filter(e -> e != null && e.contains("@"))
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Invalid email format")));
    }

    private Mono<User> findUserByEmail(String email) {
        return firebaseServiceAuth.findByEmail(email)
                .switchIfEmpty(Mono.error(new UserNotFoundException(HttpStatus.NOT_FOUND, "User not found")));
    }

    private Mono<String> generateAndStoreToken(String email) {
        String token = UUID.randomUUID().toString();
        return tokenService.saveResetToken(email, token)
                .onErrorMap(e -> new TokenGenerationException("Failed to generate token", e));
    }

    private Mono<String> sendResetEmail(String email, String token) {
        String resetLink = "https://yourapp.com/reset-password?token=" + token;
        String subject = "Password Reset Request";
        String body = String.format("""
            <html>
            <body>
                <h2>Password Reset</h2>
                <p>Click <a href="%s">here</a> to reset your password.</p>
                <p><b>This link expires in 1 hour.</b></p>
                <p>If you didn't request this, please ignore this email.</p>
            </body>
            </html>
            """, resetLink);

        return emailService.sendEmail(email, subject, body)
                .thenReturn(token)
                .onErrorMap(e -> new EmailSendingException("Failed to send email", e));
    }

    public Mono<Boolean> validateResetToken(String token) {
        return tokenService.tokenExists(token)
                .onErrorResume(e -> {
                    logger.error("Token validation error", e);
                    return Mono.just(false);
                });
    }

    public Mono<User> completePasswordReset(String token, String newPassword) {
        return validatePassword(newPassword)
                .flatMap(validPassword -> processPasswordReset(token, validPassword))
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(this::isRecoverableError)
                );
    }

    private Mono<String> validatePassword(String password) {
        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setPassword(password);

        return passwordPolicyService.validatePassword(dto)
                .map(UserRegistrationDTO::getPassword); // return password if valid
    }


    private Mono<User> processPasswordReset(String token, String newPassword) {
        return tokenService.getEmailFromToken(token)
                .switchIfEmpty(Mono.error(new InvalidTokenException("Invalid token")))
                .flatMap(this::findUserByEmail)
                .flatMap(user -> updateUserPassword(user, newPassword))
                .flatMap(user -> invalidateToken(token, user))
                .doOnSuccess(user -> logger.info("Password updated for {}", user.getEmail()))
                .doOnError(e -> logger.error("Password reset failed", e));
    }

    private Mono<User> updateUserPassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setForcePasswordChange(false);  // Reset force password flag
        return firebaseServiceAuth.save(user)
                .onErrorMap(e -> new PasswordUpdateException("Failed to update password", e));
    }

    private Mono<User> invalidateToken(String token, User user) {
        return tokenService.deleteToken(token)
                .thenReturn(user)
                .onErrorMap(e -> new TokenInvalidationException("Failed to invalidate token", e));
    }

    private boolean isRecoverableError(Throwable e) {
        return e instanceof EmailSendingException ||
                e instanceof RedisConnectionFailureException;
    }

}

