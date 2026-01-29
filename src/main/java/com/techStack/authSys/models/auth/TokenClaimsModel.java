package com.techStack.authSys.models.auth;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class TokenClaimsModel {
    private final Map<String, Object> claims;

    public TokenClaimsModel(Map<String, Object> claims) {
        this.claims = claims;
    }

    public String getUsername() {
        return (String) claims.getOrDefault("sub", "unknown");
    }
    public Optional<String> getEmail() {
        return Optional.ofNullable((String) claims.get("email"));
    }

    public String getUsernameOrEmail() {
        return getEmail().orElseGet(this::getUsername);
    }

    public List<String> getRoles() {
        return castToList(claims.get("roles"));
    }

    public List<String> getPermissions() {
        return castToList(claims.get("permissions"));
    }

    private List<String> castToList(Object value) {
        if (value instanceof List<?>) {
            return (List<String>) value;
        } else if (value instanceof String) {
            return List.of(((String) value).split(","));
        } else {
            return Collections.emptyList();
        }
    }

    public Map<String, Object> asMap() {
        return claims;
    }
}

