package com.techStack.authSys.security.authentication;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

@Component
public class CustomJwtDecoder implements JwtDecoder {

    private final JwtDecoder jwtDecoder;

    public CustomJwtDecoder() {
        this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri("https://your-auth-server.com/.well-known/jwks.json").build();
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        Jwt jwt = jwtDecoder.decode(token);
        // Add custom validation logic here
        if (!jwt.getClaimAsString("custom_claim").equals("expected_value")) {
            throw new JwtException("Invalid custom claim");
        }
        return jwt;
    }
}
