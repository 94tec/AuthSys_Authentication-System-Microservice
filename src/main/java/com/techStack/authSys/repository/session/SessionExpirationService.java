package com.techStack.authSys.repository.session;

import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Mono;

public interface SessionExpirationService {
    Mono<Void> forceLogout(String userId);
    Mono<Void> checkAndExpireSessions(String userId);

    Mono<Boolean> isSessionValid(String sessionId);

    Mono<Void> deleteSession(String sessionId);

    @Scheduled(cron = "${security.session.cleanup-cron:0 0 * * * *}")
    Mono<Void> removeExpiredSessions();
}