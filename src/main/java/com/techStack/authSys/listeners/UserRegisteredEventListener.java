package com.techStack.authSys.listeners;

import com.techStack.authSys.event.UserRegisteredEvent;
import com.techStack.authSys.service.AuditLogService;
import com.techStack.authSys.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserRegisteredEventListener {
    private static final Logger logger = LoggerFactory.getLogger(UserRegisteredEventListener.class);

    private final EmailService emailService;
    private final AuditLogService auditLogService;

    @Async
    @EventListener
    public void handleUserRegisteredEvent(UserRegisteredEvent event) {
        try {
            // Send welcome email
            emailService.sendWelcomeEmail(event.getUser().getEmail(), event.getIpAddress());

            // Log the registration
            auditLogService.logUserEvent(
                    event.getUser().getId(),
                    "USER_REGISTERED",
                    "New user registered from IP: " + event.getIpAddress()
            );

            logger.info("Processed registration event for user {}", event.getUser().getEmail());
        } catch (Exception e) {
            logger.error("Failed to process user registration event: {}", e.getMessage());
        }
    }
}
