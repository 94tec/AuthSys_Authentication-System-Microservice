package com.techStack.authSys.security.audit;

import static com.techStack.authSys.common.constants.SecurityConstants.*;

/**
 * Whitelist of log collections exposed via the generic /collections/{key}
 * endpoint. Deliberately explicit — never accept an arbitrary collection
 * name from the client, since that would let a caller read any Firestore
 * collection in the project.
 */
public enum AuditCollection {
    AUDIT("audit", "Audit Trail", AUDIT_COLLECTION),
    SECURITY("security", "Security Events", SECURITY_LOGS_COLLECTION),
    SYSTEM("system", "System Events", SYSTEM_AUDIT_COLLECTION),
    PASSWORD_CHANGE("password-change", "Password Changes", PASSWORD_CHANGE_AUDIT_COLLECTION),
    CACHE("cache", "Cache Events", CACHE_LOGS_COLLECTION),
    BOOTSTRAP("bootstrap", "Bootstrap", AUDIT_BOOTSTRAP_COLLECTION),
    ROLLBACKS("rollbacks", "Rollbacks", AUDIT_ROLLBACKS_COLLECTION),
    PARTIAL_SAVES("partial-saves", "Partial Saves", AUDIT_PARTIAL_SAVES_COLLECTION);

    public final String key;          // URL-safe identifier, e.g. "security"
    public final String label;        // human-readable, for the frontend tab
    public final String firestoreName; // actual Firestore collection name

    AuditCollection(String key, String label, String firestoreName) {
        this.key = key;
        this.label = label;
        this.firestoreName = firestoreName;
    }

    public static AuditCollection fromKey(String key) {
        for (AuditCollection c : values()) {
            if (c.key.equals(key)) return c;
        }
        throw new IllegalArgumentException("Unknown log collection: " + key);
    }
}