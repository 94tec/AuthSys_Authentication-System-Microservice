package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.sucurity.RateLimiterService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.observability.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * User Service
 *
 * Handles password lifecycle management:
 * - Change password
 * - Force password change
 * - Enforces policy, history, session invalidation, audit logging
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final PasswordHistoryService passwordHistoryService;
    private final RateLimiterService.SessionService sessionService;
    private final AuditLogService auditLogService;

    public Mono<Void> changePassword(String userId, String currentPassword, String newPassword) {
        return firebaseServiceAuth.getUserById(userId)
                .switchIfEmpty(Mono.error(new CustomException(HttpStatus.NOT_FOUND, "User not found")))
                .flatMap(user -> {
                    if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                        return Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "Current password is incorrect"));
                    }
                    return processPasswordChange(user, newPassword);
                });
    }

    public Mono<Void> forcePasswordChange(String userId, String newPassword) {
        return firebaseServiceAuth.getUserById(userId)
                .switchIfEmpty(Mono.error(new CustomException(HttpStatus.NOT_FOUND, "User not found")))
                .flatMap(user -> processPasswordChange(user, newPassword));
    }

    private Mono<Void> processPasswordChange(User user, String newPassword) {
        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setPassword(newPassword);
        dto.setUid(user.getId());

        return passwordPolicyService.validatePassword(dto)
                .then(Mono.defer(() -> {
                    user.setPassword(passwordEncoder.encode(newPassword));
                    user.setForcePasswordChange(false);
                    return firebaseServiceAuth.save(user);
                }))
                .flatMap(savedUser -> passwordHistoryService.saveToHistory(savedUser.getId(), newPassword))
                .then(sessionService.invalidateAllSessionsForUser(user.getId()))
                .then(auditLogService.logPasswordChange(user.getId(), user.getLastLoginIp()))
                .doOnSuccess(__ -> log.info("Password changed for user {}", user.getId()));
    }
}
