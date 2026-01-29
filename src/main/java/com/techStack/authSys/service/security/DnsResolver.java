package com.techStack.authSys.service.security;

import org.springframework.stereotype.Component;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.Attribute;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class DnsResolver {

    public List<String> resolveMxRecords(String domain) {
        try {
            InitialDirContext dirContext = new InitialDirContext();
            Attributes attributes = dirContext.getAttributes("dns:/" + domain, new String[]{"MX"});
            Attribute attr = attributes.get("MX");

            if (attr == null) return Collections.emptyList();

            List<String> mxRecords = new ArrayList<>();
            for (int i = 0; i < attr.size(); i++) {
                String mxRecord = (String) attr.get(i);
                mxRecords.add(mxRecord.split(" ")[1]); // Extract MX record domain
            }
            return mxRecords;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }
}

