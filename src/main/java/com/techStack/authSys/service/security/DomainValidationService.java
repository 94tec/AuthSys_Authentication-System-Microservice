package com.techStack.authSys.service.security;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.domain.InvalidDomainException;
import com.techStack.authSys.exception.service.CustomException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;

/**
 * Domain Validation Service
 *
 * Validates email domains using DNS MX record lookup.
 * Ensures only valid, active email domains are accepted.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DomainValidationService {

    private final DnsResolver dnsResolver;

    /**
     * Validate that email domain is active
     */
    public Mono<Void> validateActiveDomain(UserRegistrationDTO userDto) {
        return Mono.fromCallable(() -> {
                    String email = userDto.getEmail();
                    String domain = extractDomain(email);

                    if (!isDomainActive(domain)) {
                        throw new InvalidDomainException(
                                "Invalid or inactive email domain: " + domain
                        );
                    }

                    log.debug("Validated active domain for email: {}", email);
                    return null;

                }).subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Extract domain from email address
     */
    private String extractDomain(String email) {
        if (email == null || !email.contains("@")) {
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid email format"
            );
        }
        return email.substring(email.indexOf('@') + 1);
    }

    /**
     * Check if domain is active by verifying MX records or A record
     */
    private boolean isDomainActive(String domain) {
        try {
            // Check MX records
            List<String> mxRecords = dnsResolver.resolveMxRecords(domain);
            if (!mxRecords.isEmpty()) {
                log.debug("Domain {} has {} MX records", domain, mxRecords.size());
                return true;
            }

            // Fallback: Check A record
            boolean hasARecord = java.net.InetAddress.getByName(domain) != null;
            if (hasARecord) {
                log.debug("Domain {} has A record", domain);
                return true;
            }

            log.warn("Domain {} has no MX or A records", domain);
            return false;

        } catch (Exception e) {
            log.error("Failed to resolve domain: {}", domain, e);
            return false;
        }
    }
}