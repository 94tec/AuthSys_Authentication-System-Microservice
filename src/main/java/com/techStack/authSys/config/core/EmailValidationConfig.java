package com.techStack.authSys.config.core;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.CollectionUtils;

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Slf4j
@Data
@Configuration
@ConfigurationProperties(prefix = "email.validation")
public class EmailValidationConfig {

    // Known legitimate email providers
    private Set<String> knownProviders;

    // TLD typo mappings
    private Map<String, String> tldTypos;

    // Blocked/disposable domains
    private Set<String> blockedDomains;

    // Role-based prefixes
    private Set<String> rolePrefixes;

    // Maximum edit distance for typo detection
    private int maxEditDistance = 2;

    // Email regex pattern
    private Pattern emailRegex;

    // DNS validation timeout (ms)
    private int dnsTimeout = 5000;

    // DNS validation timeout (ms)

    // DNS server to use (optional, defaults to system DNS)
    private String dnsServer;

    // Maximum number of DNS retries
    private int dnsRetries = 2;

    // Enable/disable DNS validation (for testing)
    private boolean dnsValidationEnabled = true;

    // Cache DNS results (seconds, 0 = disabled)
    private int dnsCacheDuration = 300;

    @PostConstruct
    public void validate() {
        if (CollectionUtils.isEmpty(knownProviders)) {
            log.warn("No known providers configured for email validation");
        }

        if (CollectionUtils.isEmpty(blockedDomains)) {
            log.warn("No blocked domains configured for email validation");
        }

        if (emailRegex == null) {
            log.error("Email regex pattern is not configured!");
            throw new IllegalStateException("Email regex pattern must be configured");
        }

        log.info("Email validation configuration loaded successfully:");
        log.info("- {} known providers", knownProviders != null ? knownProviders.size() : 0);
        log.info("- {} blocked domains", blockedDomains != null ? blockedDomains.size() : 0);
        log.info("- {} role prefixes", rolePrefixes != null ? rolePrefixes.size() : 0);
        log.info("- {} TLD typos", tldTypos != null ? tldTypos.size() : 0);
    }
}