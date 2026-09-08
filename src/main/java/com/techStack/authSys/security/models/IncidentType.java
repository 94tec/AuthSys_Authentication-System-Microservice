package com.techStack.authSys.security.models;

public enum IncidentType {
    BRUTE_FORCE_LOGIN,             // repeated failed logins, same account or IP
    IMPOSSIBLE_TRAVEL,             // same account, geographically implausible successive logins
    PRIVILEGE_ESCALATION_ATTEMPT,  // lower role hitting a higher-role-only endpoint
    UNAUTHORIZED_ADMIN_ACCESS,     // /api/admin/** hit by non-super-admin or blocked IP
    API_KEY_ABUSE,                 // API key used past rate limit or from unexpected origin
    SUSPICIOUS_TOKEN_REUSE,        // JWT/session reused after invalidation or from new device
    MFA_BYPASS_ATTEMPT,
    ACCOUNT_TAKEOVER_SUSPECTED,
    MASS_DATA_EXPORT,              // unusually large export/read volume by one account
    CONFIG_TAMPERING               // repeated failed writes to system config / policies
}
