package com.techStack.authSys.security.context;

import com.techStack.authSys.dto.internal.SecurityContext;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.util.validation.ValidationUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;

/**
 * Security Context Service
 *
 * Manages security context creation and validation.
 * Uses Clock for timestamp generation.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class SecurityContextService {

    private final RoleAssignmentService roleAssignmentService;
    private final Clock clock;

    /* =========================
       Context Creation
       ========================= */

    /**
     * Get current security context from authentication
     */
    public Mono<SecurityContext> getCurrentSecurityContext(Authentication authentication) {
        Instant now = clock.instant();

        return Mono.fromCallable(() -> {
            ValidationUtils.validateNotNull(authentication, "Authentication cannot be null");

            String email = authentication.getName();
            Roles highestRole = roleAssignmentService.extractHighestRole(authentication);

            return SecurityContext.builder()
                    .requesterEmail(email)
                    .requesterRole(highestRole)
                    .authenticationTime(now)
                    .build();

        }).doOnSuccess(context ->
                log.debug("🔒 Security context created for: {} ({}) at {}",
                        context.getRequesterEmail(),
                        context.getRequesterRole(),
                        now));
    }
}
