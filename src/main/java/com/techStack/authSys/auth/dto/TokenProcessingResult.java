package com.techStack.authSys.auth.dto;

import com.techStack.authSys.security.models.TokenType;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

/**
 * Token processing result
 */
public record TokenProcessingResult(
        String userId,
        String email,
        TokenType tokenType,
        Map<String, Object> claims,
        Collection<GrantedAuthority> authorities
) {}
