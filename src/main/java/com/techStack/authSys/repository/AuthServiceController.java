package com.techStack.authSys.repository;

import com.techStack.authSys.dto.AuthResult;
import com.techStack.authSys.event.AccountLockedEvent;
import com.techStack.authSys.models.User;
import org.springframework.context.event.EventListener;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.scheduling.annotation.Async;
import reactor.core.publisher.Mono;

public interface AuthServiceController {
    @Async
    @EventListener
    void handleAccountLockedEvent(AccountLockedEvent event);

    Mono<AuthResult> authenticate(String userId, String email, String password, String ipAddress, String deviceFingerprint, String userAgent, String issuedAt);

    Mono<AuthResult> performAuthentication(String email, String password, String ipAddress, String deviceFingerprint, String issuedAt);

    Mono<AuthResult> performAuthentication(String email, String password, String issuedAt, String ipAddress);

    Mono<AuthResult> generateAndPersistTokens(User user, String ipAddress, String deviceFingerprint, String userAgent);

    //Mono<AuthResult> generateAndPersistTokens(User user, ServerHttpRequest request, String deviceFingerprint, String userAgent);
}


