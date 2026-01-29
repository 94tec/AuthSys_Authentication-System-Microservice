package com.techStack.authSys.util.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
public class AuthContextService {

    public String getCurrentUserId() {
        Jwt jwt = getJwt();
        return jwt.getSubject(); // "sub" claim (typically userId)
    }

    public String getCurrentEmail() {
        Jwt jwt = getJwt();
        return jwt.getClaimAsString("email"); // only if you added email as a claim
    }

    public boolean hasRole(String role) {
        Jwt jwt = getJwt();
        return jwt.getClaimAsStringList("roles").contains(role);
    }

    public Jwt getJwt() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt;
        }
        throw new IllegalStateException("JWT not found in security context");
    }
}

