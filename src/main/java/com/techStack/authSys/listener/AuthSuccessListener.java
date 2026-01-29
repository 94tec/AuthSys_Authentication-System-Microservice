package com.techStack.authSys.listener;


import com.techStack.authSys.event.AuthSuccessEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthSuccessListener {

    @EventListener
    public void onAuthSuccess(AuthSuccessEvent event) {
        log.info("User {} authenticated successfully from IP: {}", event.getUser().getEmail(), event.getIpAddress());

        // ✅ Additional actions (e.g., audit logging, notifying other services, etc.)
    }
}

