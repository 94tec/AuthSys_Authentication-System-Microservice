package com.techStack.authSys.security.authentication;

import com.techStack.authSys.service.auth.FirebaseAuthenticationManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class FirebaseSecurityContextRepository implements ServerSecurityContextRepository {

    private static final Logger logger = LoggerFactory.getLogger(FirebaseSecurityContextRepository.class);
    private final FirebaseAuthenticationManager authenticationManager;
    private final ServerBearerTokenAuthenticationConverter tokenConverter;

    public FirebaseSecurityContextRepository(FirebaseAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        this.tokenConverter = new ServerBearerTokenAuthenticationConverter();
        this.tokenConverter.setAllowUriQueryParameter(false); // Disable token in URL for security
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty(); // Stateless JWT - no session persistence
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        return Mono.defer(() -> tokenConverter.convert(exchange))
                .doOnNext(auth -> logTokenConversion(exchange, auth))
                .flatMap(this::authenticateAndBuildContext)
                .doOnSuccess(this::logSuccessfulAuthentication)
                .onErrorResume(e -> handleAuthenticationError(exchange, e));
    }

    private Mono<SecurityContext> authenticateAndBuildContext(Authentication authToken) {
        return authenticationManager.authenticate(authToken)
                .map(authenticated -> {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Building security context for user: {} with authorities: {}",
                                authenticated.getName(),
                                authenticated.getAuthorities());
                    }
                    return new SecurityContextImpl(authenticated);
                });
    }

    private void logTokenConversion(ServerWebExchange exchange, Authentication auth) {
        if (logger.isDebugEnabled()) {
            String path = exchange.getRequest().getPath().toString();
            logger.debug("Token conversion for path {}: {}", path, auth);
        }
    }

    private void logSuccessfulAuthentication(SecurityContext context) {
        if (logger.isDebugEnabled()) {
            Authentication auth = context.getAuthentication();
            logger.debug("Authentication successful for user: {} with roles: {}",
                    auth.getName(),
                    auth.getAuthorities());
        }
    }

    private Mono<SecurityContext> handleAuthenticationError(ServerWebExchange exchange, Throwable e) {
        String path = exchange.getRequest().getPath().toString();
        String method = exchange.getRequest().getMethod().name();

        logger.warn("Authentication failed for {} {}: {}", method, path, e.getMessage());

        // Return empty Mono to continue the chain (will be handled by AuthenticationEntryPoint)
        return Mono.empty();
    }
}