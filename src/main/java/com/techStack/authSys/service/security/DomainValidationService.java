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

import java.util.List;


@Service
@RequiredArgsConstructor
public class DomainValidationService {
    private static final Logger logger = LoggerFactory.getLogger(DomainValidationService.class);

    private final DnsResolver dnsResolver;

    public Mono<UserDTO> validateActiveDomain(UserDTO userDto) {
        return Mono.fromCallable(() -> {
            String email = userDto.getEmail();
            String domain = extractDomain(userDto.getEmail());

            if (!isDomainActive(domain)) {
                throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid or inactive email domain.");
            }

            logger.info("Validated active domain for email: {}", email);
            return userDto;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private String extractDomain(String email) {
        if (email == null || !email.contains("@")) {
            throw new CustomException(HttpStatus.BAD_REQUEST, "Invalid email format.");
        }
        return email.substring(email.indexOf('@') + 1);
    }

    private boolean isDomainActive(String domain) {
        try {
            List<String> mxRecords = dnsResolver.resolveMxRecords(domain);
            boolean hasMxRecords = !mxRecords.isEmpty();
            boolean hasARecord = java.net.InetAddress.getByName(domain) != null;

            return hasMxRecords || hasARecord;
        } catch (Exception e) {
            logger.error("Failed to resolve domain: {}", domain, e);
            return false;
        }
    }
}
