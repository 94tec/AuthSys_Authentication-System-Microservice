package com.techStack.authSys.repository.authorization;

import java.util.List;

/**
 * DnsResolver Interface
 * Solution: Make DnsResolver an interface, DnsJavaResolver is the impl.
 */
public interface DnsResolver {

    /**
     * Resolve MX records for a domain.
     *
     * @param domain the email domain (e.g. "gmail.com")
     * @return list of MX hostnames, empty if none found
     */
    List<String> resolveMxRecords(String domain);

    /* =========================
           A Record Lookup
           ========================= */
    boolean hasARecord(String domain);
}