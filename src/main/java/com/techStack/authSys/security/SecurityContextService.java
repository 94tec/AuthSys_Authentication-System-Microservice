package com.techStack.authSys.security;

import com.techStack.authSys.dto.SecurityContext;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.service.RoleAssignmentService;
import com.techStack.authSys.util.ValidationUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import com.techStack.authSys.dto.SecurityContext;
import com.techStack.authSys.models.Roles;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Clean security context management
 */

@Service
@Slf4j
public class SecurityContextService {
    @Autowired
    private final RoleAssignmentService roleAssignmentService;

    public SecurityContextService(RoleAssignmentService roleAssignmentService) {
        this.roleAssignmentService = roleAssignmentService;
    }

    public Mono<SecurityContext> getCurrentSecurityContext(Authentication authentication) {
        return Mono.fromCallable(() -> {
            ValidationUtils.validateNotNull(authentication, "Authentication cannot be null");

            String email = authentication.getName();
            Roles highestRole = roleAssignmentService.extractHighestRole(authentication);

            return SecurityContext.builder()
                    .requesterEmail(email)
                    .requesterRole(highestRole)
                    .authenticationTime(Instant.now())
                    .build();
        }).doOnSuccess(context ->
                log.debug("🔒 Security context created for: {} ({})", context.getRequesterEmail(), context.getRequesterRole()));
    }

}
