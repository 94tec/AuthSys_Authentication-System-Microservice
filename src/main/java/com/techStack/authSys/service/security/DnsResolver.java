package com.techStack.authSys.service.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

@Slf4j
@Component
public class DnsResolver {

    /**
     * Resolve MX records for a domain using JNDI DNS.
     */
    public List<String> resolveMxRecords(String domain) {
        if (domain == null || domain.isBlank()) {
            return Collections.emptyList();
        }

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");

            DirContext dirContext = new InitialDirContext(env);

            Attributes attributes = dirContext.getAttributes(domain, new String[]{"MX"});
            Attribute mxAttribute = attributes.get("MX");

            if (mxAttribute == null) {
                return Collections.emptyList();
            }

            List<String> mxRecords = new ArrayList<>();
            NamingEnumeration<?> values = mxAttribute.getAll();

            while (values.hasMore()) {
                String record = values.next().toString();
                // Example: "10 mail.example.com."
                String[] parts = record.split("\\s+");
                if (parts.length >= 2) {
                    mxRecords.add(parts[1].trim());
                }
            }

            return mxRecords;

        } catch (Exception e) {
            log.debug("MX lookup failed for domain {}: {}", domain, e.getMessage());
            return Collections.emptyList();
        }
    }
}
