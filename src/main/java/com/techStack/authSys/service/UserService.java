package com.techStack.authSys.service;

import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.AuthRepository;
import com.techStack.authSys.repository.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final AuthRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final PasswordHistoryService passwordHistoryService;
    private final RateLimiterService.SessionService sessionService;
    private final AuditLogService auditLogService;

    public Mono<Void> changePassword(String userId, String currentPassword, String newPassword) {
        return userRepository.findById(userId)
                .switchIfEmpty(Mono.error(new CustomException(HttpStatus.NOT_FOUND, "User not found")))
                .flatMap(user -> {
                    // Verify current password
                    if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                        return Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "Current password is incorrect"));
                    }
                    return processPasswordChange(user, newPassword);
                });
    }

    public Mono<Void> forcePasswordChange(String userId, String newPassword) {
        return userRepository.findById(userId)
                .switchIfEmpty(Mono.error(new CustomException(HttpStatus.NOT_FOUND, "User not found")))
                .flatMap(user -> processPasswordChange(user, newPassword));
    }

    private Mono<Void> processPasswordChange(User user, String newPassword) {
        // Validate against password policy
        UserDTO dto = new UserDTO();
        dto.setPassword(newPassword);
        dto.setUid(user.getId());

        return passwordPolicyService.validatePassword(dto)
                .then(Mono.defer(() -> {
                    // Update password
                    user.setPassword(passwordEncoder.encode(newPassword));
                    user.setForcePasswordChange(false);
                    return userRepository.save(user);
                }))
                .flatMap(savedUser -> passwordHistoryService.saveToHistory(savedUser.getId(), newPassword))
                .then(sessionService.invalidateAllSessionsForUser(user.getId()))
                .then(auditLogService.logPasswordChange(user.getId(), user.getLastLoginIpAddress()))
                .doOnSuccess(__ -> log.info("Password changed for user {}", user.getId()));
    }
}
