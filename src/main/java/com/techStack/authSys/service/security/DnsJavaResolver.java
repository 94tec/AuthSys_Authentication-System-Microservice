package com.techStack.authSys.service.security;

import com.techStack.authSys.config.core.EmailValidationConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * DNS Resolver using DNSJava (more reliable than JNDI).
 *
 * ✅ FIXED:
 *  1. Removed @RequiredArgsConstructor — conflicts with manual constructor
 *     that throws checked UnknownHostException.
 *  2. DnsResolver is now an interface — this class is the @Primary impl.
 *  3. Old JNDI DnsResolver.java concrete class must be DELETED.
 */
@Slf4j
@Component
public class DnsJavaResolver implements DnsResolver {

    private final EmailValidationConfig config;
    private final SimpleResolver resolver;

    /* ✅ FIXED: Single explicit constructor — no @RequiredArgsConstructor */
    public DnsJavaResolver(EmailValidationConfig config) throws UnknownHostException {
        this.config = config;

        String dnsServer = (config.getDnsServer() != null && !config.getDnsServer().isBlank())
                ? config.getDnsServer()
                : "8.8.8.8";  // Google DNS fallback

        this.resolver = new SimpleResolver(dnsServer);
        this.resolver.setTimeout(Duration.ofMillis(config.getDnsTimeout()));

        log.info("DnsJavaResolver initialized with server: {} timeout: {}ms",
                dnsServer, config.getDnsTimeout());
    }

    /* =========================
       MX Record Lookup
       ========================= */

    @Override
    public List<String> resolveMxRecords(String domain) {
        if (domain == null || domain.isBlank()) {
            return Collections.emptyList();
        }

        CompletableFuture<List<String>> future = CompletableFuture.supplyAsync(() -> {
            try {
                Lookup lookup = new Lookup(domain, Type.MX);
                lookup.setResolver(resolver);
                lookup.setCache(null); // Fresh lookup every time

                Record[] records = lookup.run();

                if (lookup.getResult() == Lookup.SUCCESSFUL && records != null) {
                    return Arrays.stream(records)
                            .map(r -> (MXRecord) r)
                            .sorted((a, b) -> Integer.compare(a.getPriority(), b.getPriority()))
                            .map(mx -> mx.getTarget().toString(true)) // strip trailing dot
                            .collect(Collectors.toList());
                }

                log.debug("No MX records for domain: {} ({})", domain, lookup.getErrorString());
                return Collections.emptyList();

            } catch (Exception e) {
                log.debug("MX lookup failed for domain {}: {}", domain, e.getMessage());
                return Collections.emptyList();
            }
        });

        try {
            return future.get(config.getDnsTimeout(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            log.warn("DNS MX lookup timed out for domain: {}", domain);
            future.cancel(true);
            return Collections.emptyList();
        } catch (Exception e) {
            log.debug("DNS MX lookup error for domain {}: {}", domain, e.getMessage());
            return Collections.emptyList();
        }
    }

    /* =========================
       A Record Lookup
       ========================= */

    public boolean hasARecord(String domain) {
        try {
            Lookup lookup = new Lookup(domain, Type.A);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();
            return lookup.getResult() == Lookup.SUCCESSFUL
                    && records != null
                    && records.length > 0;
        } catch (Exception e) {
            log.debug("A record lookup failed for domain {}: {}", domain, e.getMessage());
            return false;
        }
    }

    /* =========================
       TXT Record Lookup
       ========================= */

    public List<String> resolveTxtRecords(String domain) {
        try {
            Lookup lookup = new Lookup(domain, Type.TXT);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();

            if (lookup.getResult() == Lookup.SUCCESSFUL && records != null) {
                return Arrays.stream(records)
                        .map(r -> ((TXTRecord) r).getStrings().toString())
                        .collect(Collectors.toList());
            }
        } catch (Exception e) {
            log.debug("TXT lookup failed for domain {}: {}", domain, e.getMessage());
        }
        return Collections.emptyList();
    }
}
