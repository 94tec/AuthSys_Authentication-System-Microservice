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

import java.net.InetAddress;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class DomainValidationService {

    private final DnsResolver dnsResolver;

    /**
     * Validate that email domain is active (has MX or A record).
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

                    log.debug("✅ Active email domain validated: {}", domain);
                    return true;

                }).subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    private String extractDomain(String email) {
        if (email == null || !email.contains("@")) {
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid email format",
                    "email",
                    "ERROR_EMAIL_INVALID"
            );
        }
        return email.substring(email.indexOf('@') + 1).trim().toLowerCase();
    }

    /**
     * Domain is active if it has MX records or at least resolves to an IP (A record).
     */
    private boolean isDomainActive(String domain) {
        try {
            // 1) MX lookup
            List<String> mxRecords = dnsResolver.resolveMxRecords(domain);
            if (!mxRecords.isEmpty()) {
                log.debug("Domain {} has MX records: {}", domain, mxRecords);
                return true;
            }

            // 2) A record fallback
            InetAddress address = InetAddress.getByName(domain);
            boolean hasARecord = address != null;

            if (hasARecord) {
                log.debug("Domain {} resolves to IP: {}", domain, address.getHostAddress());
                return true;
            }

            log.warn("Domain {} has no MX and no A record", domain);
            return false;

        } catch (Exception e) {
            log.warn("Domain lookup failed for {}: {}", domain, e.getMessage());
            return false;
        }
    }
}
