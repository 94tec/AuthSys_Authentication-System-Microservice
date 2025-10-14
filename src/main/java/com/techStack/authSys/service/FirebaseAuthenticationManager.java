package com.techStack.authSys.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.models.TokenClaimsModel;
import com.techStack.authSys.models.User;
import com.techStack.authSys.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Primary
@Service
@RequiredArgsConstructor
public class FirebaseAuthenticationManager implements ReactiveAuthenticationManager {

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String PERM_PREFIX = "PERM_";
    private static final String DEFAULT_ROLE = "ROLE_USER";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_PERMISSIONS = "permissions";
    private static final String CLAIM_TYPE = "type";
    private static final String CLAIM_TYPE_ACCESS = "access";

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final JwtService jwtService;
    private final FirebaseTokenCacheService firebaseTokenCacheService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RedisCacheService redisCacheService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication)
                .flatMap(this::extractAndValidateToken)
                .flatMap(this::processToken)
                .doOnSuccess(this::logSuccessfulAuthentication)
                .doOnError(e -> log.error("Authentication failed: {}", e.getMessage()))
                .onErrorResume(this::handleAuthenticationError);
    }
    private Mono<String> extractAndValidateToken(Authentication authentication) {
        return Mono.justOrEmpty(authentication.getCredentials())
                .cast(String.class)
                .filter(token -> !token.isBlank())
                //.doOnNext(token -> log.info("🔐 Validating extracted token: {}", token))
                .switchIfEmpty(Mono.error(new AuthenticationServiceException("Missing or empty token")));
    }

    private Mono<Authentication> processToken(String token) {
        return determineTokenType(token)
                .flatMap(tokenType -> {
                    switch (tokenType) {
                        case FIREBASE:
                            return authenticateFirebaseToken(token)
                                    .timeout(Duration.ofSeconds(5));
                        case CUSTOM_JWT:
                            return authenticateCustomJwt(token)
                                    .timeout(Duration.ofSeconds(5));
                        default:
                            return Mono.error(new AuthenticationServiceException("Unsupported token type"));
                    }
                })
                .doOnSuccess(auth -> log.info("Authentication successful"))
                .doOnError(e -> log.error("Authentication failed", e));
    }

    public Mono<TokenType> determineTokenType(String token) {
        return Mono.fromCallable(() -> {
            if (isFirebaseToken(token)) return TokenType.FIREBASE;
            if (isCustomJwt(token)) return TokenType.CUSTOM_JWT;
            throw new AuthenticationServiceException("Unsupported token type");
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private boolean isFirebaseToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return false;

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode payload = objectMapper.readTree(payloadJson);
            return payload.has("iss") &&
                    payload.get("iss").asText().startsWith("https://securetoken.google.com/");
        } catch (Exception e) {
            log.debug("Failed to parse token payload", e);
            return false;
        }
    }

    private boolean isCustomJwt(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return false;

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode json = objectMapper.readTree(payload);
            return json.has(CLAIM_TYPE) && CLAIM_TYPE_ACCESS.equalsIgnoreCase(json.get(CLAIM_TYPE).asText());
        } catch (Exception e) {
            log.debug("Token parsing failed", e);
            return false;
        }
    }

    private Mono<Authentication> authenticateFirebaseToken(String token) {
        return firebaseTokenCacheService.getCachedToken(token)
                .switchIfEmpty(Mono.defer(() -> verifyAndCacheFirebaseToken(token)))
                .map(this::createAuthentication)
                .onErrorResume(e -> Mono.error(
                        new AuthenticationServiceException("Firebase token validation failed: " + e.getMessage())));
    }

    private Mono<Authentication> authenticateCustomJwt(String token) {
        return redisCacheService.getCachedClaims(token)
                .flatMap(this::castToClaimsMap)
                .switchIfEmpty(Mono.defer(() -> validateAndCacheFreshToken(token)))
                .flatMap(this::buildAuthentication)
                .onErrorResume(e -> {
                    Throwable ex = (e instanceof Throwable) ? (Throwable) e : new RuntimeException("Unknown error");
                    return Mono.error(new AuthenticationServiceException("JWT validation failed: " + ex.getMessage()));
                });

    }

    public Mono<FirebaseToken> verifyAndCacheFirebaseToken(String token) {
        return Mono.fromCallable(() -> FirebaseAuth.getInstance().verifyIdToken(token))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(decoded -> firebaseTokenCacheService.cacheToken(token, decoded)
                        .thenReturn(decoded));
    }

    public Mono<Map<String, Object>> validateAndCacheFreshToken(String token) {
        return jwtService.validateToken(token, CLAIM_TYPE_ACCESS)
                .flatMap(claims -> cacheClaimsWithFallback(token, claims))
                .onErrorResume(e -> {
                    log.warn("Token validation failed", e);
                    return Mono.error(new AuthenticationServiceException("Invalid token"));
                });
    }

    public Mono<Map> castToClaimsMap(Object claims) {
        return Mono.just(claims)
                .filter(Map.class::isInstance)
                .cast(Map.class)
                .switchIfEmpty(Mono.error(new AuthenticationServiceException("Invalid claims format")));
    }

    private Mono<Map<String, Object>> cacheClaimsWithFallback(String token, Map<String, Object> claims) {
        return redisCacheService.cacheClaims(token, claims)
                .onErrorResume(e -> {
                    log.warn("Failed to cache claims", e);
                    return Mono.empty(); // Continue with claims even if caching fails
                })
                .thenReturn(claims);
    }

    private Authentication createAuthentication(FirebaseToken token) {
        return new UsernamePasswordAuthenticationToken(
                token.getUid(),
                null,
                extractAuthorities(token.getClaims()));
    }

    private Mono<Authentication> buildAuthentication(Map<String, Object> claims) {
        return Mono.fromCallable(() -> new TokenClaimsModel(claims))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(claimsModel -> {
                    // Try email first, then fall back to username
                    String userIdentifier = claimsModel.getEmail()
                            .orElseGet(claimsModel::getUsername);

                    return firebaseServiceAuth.findByEmail(userIdentifier)
                            .switchIfEmpty(Mono.error(new AuthenticationServiceException(
                                    "User not found for identifier: " + userIdentifier)))
                            .map(user -> {
                                // Add forcePasswordChange flag to authentication if needed
                                log.info("DIRECT DATABASE LOAD - forcePasswordChange: {}", user.isForcePasswordChange());
                                boolean forceChange = Boolean.TRUE.equals(claims.get("forcePasswordChange"));
                                user.setForcePasswordChange(forceChange);
                                return createAuthenticationToken(user, claimsModel);
                            });
                });
    }

    private Authentication createAuthenticationToken(User user, TokenClaimsModel claims) {
        // 1. Fresh load with verification
        user = firebaseServiceAuth.findByEmail(user.getEmail()).block();
        assert user != null;
        log.info("TOKEN CREATION - Fresh load forceChange: {}", user.isForcePasswordChange());

        // 2. Validate expected state
        if (!user.isForcePasswordChange()) {
            log.error("DATA INCONSISTENCY: DB=true but loaded={}", false);
        }
        // Add debug logging
        log.info("Creating token for {} - {} - forcePasswordChange: {}",
                user.getEmail(), user.getRoles(), user.isForcePasswordChange());
        CustomUserDetails userDetails = new CustomUserDetails(
                user,
                claims.getRoles(),
                claims.getPermissions()
        );

        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }

    public Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Process roles
        extractRoles(claims).forEach(role ->
                authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role)));

        // Process permissions
        extractPermissions(claims).forEach(perm ->
                authorities.add(new SimpleGrantedAuthority(PERM_PREFIX + perm)));

        return authorities.isEmpty()
                ? List.of(new SimpleGrantedAuthority(DEFAULT_ROLE))
                : authorities;
    }
    private Set<String> extractClaimSet(Object claim) {
        if (claim instanceof String s) {
            return Arrays.stream(s.split(","))
                    .map(String::trim)
                    .filter(s1 -> !s1.isEmpty())
                    .map(String::toUpperCase)
                    .collect(Collectors.toSet());
        } else if (claim instanceof List<?> list) {
            return list.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .map(String::toUpperCase)
                    .collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }
    private Set<String> extractRoles(Map<String, Object> claims) {
        Set<String> roles = extractClaimSet(claims.get(CLAIM_ROLE));
        roles.addAll(extractClaimSet(claims.get(CLAIM_ROLES)));
        return roles;
    }
    private Set<String> extractPermissions(Map<String, Object> claims) {
        Object raw = claims.get(CLAIM_PERMISSIONS);
        return extractClaimSet(raw);
    }

    private void logSuccessfulAuthentication(Authentication auth) {
        if (log.isDebugEnabled()) {
            String authorities = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(", "));

            log.info("Authenticated user: {} with authorities: {}", auth.getName(), authorities);
        }
    }

    private Mono<Authentication> handleAuthenticationError(Throwable e) {
        if (e instanceof AuthenticationServiceException) {
            return Mono.error(e);
        }
        return Mono.error(new AuthenticationServiceException("Authentication failed", e));
    }

    private enum TokenType {
        FIREBASE, CUSTOM_JWT
    }
}