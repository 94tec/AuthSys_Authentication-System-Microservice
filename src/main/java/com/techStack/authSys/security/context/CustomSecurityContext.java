package com.techStack.authSys.security.context;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;

public class CustomSecurityContext implements SecurityContext {
    private final Authentication authentication;

    public CustomSecurityContext(Authentication authentication) {
        this.authentication = authentication;
    }

    @Override
    public Authentication getAuthentication() {
        return authentication;
    }

    @Override
    public void setAuthentication(Authentication authentication) {
        throw new UnsupportedOperationException("Immutable context");
    }
}

