package com.techStack.authSys.service.security;

import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.exception.service.CustomException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class SuspiciousActivityService {
    private static final Logger logger = LoggerFactory.getLogger(SuspiciousActivityService.class);

    // Simulated blacklists (Replace with DB or Redis)
    private static final Set<String> BLACKLISTED_IPS = Set.of("192.168.1.100", "10.0.0.50");
    private static final Set<String> BLACKLISTED_EMAILS = Set.of("test@spam.com", "fake@mailinator.com");

    // Rate limiting: Tracks last registration attempt from each IP
    private static final Map<String, Long> recentRegistrations = new ConcurrentHashMap<>();
    private static final long REGISTRATION_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutes

    public Mono<Void> checkPatterns(String email, String ipAddress, UserDTO.RegistrationMetadata metadata) {
        return Mono.fromRunnable(() -> {
                    // Skip localhost during testing
                    if ("127.0.0.1".equals(ipAddress) || "::1".equals(ipAddress) || "localhost".equalsIgnoreCase(ipAddress)) {
                        logger.info("Skipping suspicious activity check for localhost IP: {}", ipAddress);
                        return;
                    }

                    if (BLACKLISTED_IPS.contains(ipAddress)) {
                        logger.warn("Blacklisted IP detected: {}", ipAddress);
                        throw new CustomException(HttpStatus.FORBIDDEN, "Suspicious IP detected.");
                    }

                    if (BLACKLISTED_EMAILS.contains(email)) {
                        logger.warn("Blacklisted email detected: {}", email);
                        throw new CustomException(HttpStatus.FORBIDDEN, "Suspicious email detected.");
                    }

                    if (isHoneypotTriggered(metadata)) {
                        logger.warn("Honeypot triggered for email: {}", email);
                        throw new CustomException(HttpStatus.FORBIDDEN, "Suspicious activity detected.");
                    }

                    long now = System.currentTimeMillis();

                    // Remove expired entries safely using an iterator
                    Iterator<Map.Entry<String, Long>> iterator = recentRegistrations.entrySet().iterator();
                    while (iterator.hasNext()) {
                        Map.Entry<String, Long> entry = iterator.next();
                        if (now - entry.getValue() > REGISTRATION_COOLDOWN_MS) {
                            iterator.remove();
                        }
                    }

                    // Rate limit check
                    if (recentRegistrations.containsKey(ipAddress)) {
                        long lastAttempt = recentRegistrations.get(ipAddress);
                        if (now - lastAttempt < REGISTRATION_COOLDOWN_MS) {
                            logger.warn("Too many registrations detected from the same IP: {}", ipAddress);
                            throw new CustomException(HttpStatus.TOO_MANY_REQUESTS, "Too many registration attempts from this IP.");
                        }
                    }

                    // Register this attempt
                    recentRegistrations.put(ipAddress, now);
                    logger.info("Suspicious activity check passed for email: {}", email);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> logger.error("Suspicious activity check failed for email: {}", email, e))
                .onErrorResume(e -> Mono.error(e instanceof CustomException ? e : new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Error detecting suspicious activity.")))
                .then();
    }

    private boolean isHoneypotTriggered(UserDTO.RegistrationMetadata metadata) {
        return metadata != null && metadata.getHoneypot() != null && !metadata.getHoneypot().isEmpty();
    }
}
