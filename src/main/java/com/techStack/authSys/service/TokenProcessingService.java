package com.techStack.authSys.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TokenProcessingService {
    private static final Logger log = LoggerFactory.getLogger(TokenProcessingService.class);

    // Constants for claim processing
    private static final String ROLE_PREFIX = "ROLE_";
    private static final String PERM_PREFIX = "PERM_";
    private static final String DEFAULT_ROLE = "ROLE_USER";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMISSIONS = "permissions";
    private static final String CLAIM_TYPE = "type";
    private static final String CLAIM_TYPE_ACCESS = "access";

    private final FirebaseTokenCacheService firebaseTokenCacheService;
    private final RedisCacheService redisCacheService;
    private final JwtService jwtValidationService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public Mono<TokenProcessingResult> processToken(String token) {
        return Mono.fromCallable(() -> new SafeToken(token))
                .flatMap(this::processTokenSafely)
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<TokenProcessingResult> processTokenSafely(SafeToken safeToken) {
        return determineTokenType(safeToken.getToken())
                .flatMap(tokenType -> switch (tokenType) {
                    case FIREBASE -> processFirebaseToken(safeToken);
                    case CUSTOM_JWT -> processJwtToken(safeToken);
                })
                .doOnSuccess(result -> logAuthSuccess(result.userId()))
                .doOnError(e -> logAuthFailure(safeToken.getFingerprint(), e));
    }

    private Mono<TokenType> determineTokenType(String token) {
        return Mono.fromCallable(() -> {
            verifyTokenNotEmpty(token);
            verifyTokenStructure(token);

            if (isFirebaseToken(token)) return TokenType.FIREBASE;
            if (isCustomJwt(token)) return TokenType.CUSTOM_JWT;

            throw new AuthenticationServiceException("Unsupported token type");
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private void verifyTokenNotEmpty(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthenticationServiceException("Empty token");
        }
    }

    private void verifyTokenStructure(String token) {
        if (token.split("\\.").length != 3) {
            throw new AuthenticationServiceException("Invalid JWT structure");
        }
    }

    private boolean isFirebaseToken(String token) {
        try {
            JsonNode payload = extractTokenPayload(token);
            return payload.has("iss") &&
                    payload.get("iss").asText().startsWith("https://securetoken.google.com/");
        } catch (Exception e) {
            log.debug("Firebase token check failed", e);
            return false;
        }
    }

    private boolean isCustomJwt(String token) {
        try {
            JsonNode payload = extractTokenPayload(token);
            return payload.has(CLAIM_TYPE) &&
                    CLAIM_TYPE_ACCESS.equalsIgnoreCase(payload.get(CLAIM_TYPE).asText());
        } catch (Exception e) {
            log.debug("Custom JWT check failed", e);
            return false;
        }
    }

    private JsonNode extractTokenPayload(String token) throws Exception {
        String[] parts = token.split("\\.");
        String payloadJson = new String(
                Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8
        );
        return objectMapper.readTree(payloadJson);
    }

    private Mono<TokenProcessingResult> processFirebaseToken(SafeToken safeToken) {
        return firebaseTokenCacheService.getCachedToken(safeToken.getToken())
                .switchIfEmpty(Mono.defer(() -> verifyAndCacheFirebaseToken(safeToken)))
                .map(this::createFirebaseTokenResult)
                .onErrorResume(e -> handleAuthError("Firebase", safeToken.getFingerprint(), e));
    }

    private Mono<FirebaseToken> verifyAndCacheFirebaseToken(SafeToken safeToken) {
        return Mono.fromCallable(() -> FirebaseAuth.getInstance().verifyIdToken(safeToken.getToken()))
                .flatMap(decoded -> firebaseTokenCacheService.cacheToken(safeToken.getToken(), decoded)
                        .thenReturn(decoded))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<TokenProcessingResult> processJwtToken(SafeToken safeToken) {
        return redisCacheService.getCachedClaims(safeToken.getToken())
                .flatMap(this::createMutableClaimsMap)
                .switchIfEmpty(Mono.defer(() -> validateAndCacheJwtToken(safeToken)))
                .map(this::createJwtTokenResult)
                .onErrorResume(e -> handleAuthError("JWT", safeToken.getFingerprint(), e));
    }

    private Mono<Map<String, Object>> createMutableClaimsMap(Object claims) {
        return Mono.fromCallable(() -> {
            if (!(claims instanceof Map)) {
                throw new AuthenticationServiceException("Invalid claims format");
            }
            return makeMutable((Map<?, ?>) claims);
        });
    }

    private Mono<Map<String, Object>> validateAndCacheJwtToken(SafeToken safeToken) {
        return jwtValidationService.validateToken(safeToken.getToken(), CLAIM_TYPE_ACCESS)
                .flatMap(claims -> cacheClaimsWithFallback(safeToken.getToken(), claims));
    }

    private Mono<Map<String, Object>> cacheClaimsWithFallback(String token, Map<String, Object> claims) {
        return redisCacheService.cacheClaims(token, claims)
                .onErrorResume(e -> {
                    log.warn("Failed to cache claims", e);
                    return Mono.empty(); // Continue with claims even if caching fails
                })
                .thenReturn(claims);
    }

    private TokenProcessingResult createFirebaseTokenResult(FirebaseToken token) {
        return new TokenProcessingResult(
                token.getUid(),
                token.getEmail(),
                TokenType.FIREBASE,
                makeMutable(token.getClaims()),
                extractAuthorities(token.getClaims())
        );
    }

    private TokenProcessingResult createJwtTokenResult(Map<String, Object> claims) {
        return new TokenProcessingResult(
                claims.get("sub").toString(),
                (String) claims.get("email"),
                TokenType.CUSTOM_JWT,
                claims,
                extractAuthorities(claims)
        );
    }

    private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        extractRoles(claims).forEach(role ->
                authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role)));

        extractPermissions(claims).forEach(perm ->
                authorities.add(new SimpleGrantedAuthority(PERM_PREFIX + perm)));

        return authorities.isEmpty() ?
                Set.of(new SimpleGrantedAuthority(DEFAULT_ROLE)) :
                authorities;
    }

    private Set<String> extractRoles(Map<String, Object> claims) {
        Set<String> roles = extractClaimValues(claims.get(CLAIM_ROLES));
        roles.addAll(extractClaimValues(claims.get("role"))); // Legacy support
        return roles;
    }

    private Set<String> extractPermissions(Map<String, Object> claims) {
        return extractClaimValues(claims.get(CLAIM_PERMISSIONS));
    }

    private Set<String> extractClaimValues(Object claim) {
        if (claim instanceof String s) {
            return Arrays.stream(s.split(","))
                    .map(String::trim)
                    .filter(s1 -> !s1.isEmpty())
                    .collect(Collectors.toSet());
        } else if (claim instanceof Collection<?> collection) {
            return collection.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }

    private Map<String, Object> makeMutable(Map<?, ?> original) {
        Map<String, Object> mutable = new HashMap<>();
        original.forEach((k, v) -> mutable.put(k.toString(), makeMutableValue(v)));
        return mutable;
    }

    private Object makeMutableValue(Object value) {
        if (value instanceof Map<?, ?> map) return makeMutable(map);
        if (value instanceof Collection<?> coll) return new ArrayList<>(coll);
        return value;
    }

    private void logAuthSuccess(String userId) {
        log.info("Authentication successful for user: {}", userId);
    }

    private void logAuthFailure(String tokenFingerprint, Throwable e) {
        log.error("Authentication failed for token: {}. Error: {}", tokenFingerprint, e.getMessage());
    }

    private <T> Mono<T> handleAuthError(String tokenType, String fingerprint, Throwable e) {
        log.error("{} token validation failed for: {}. Error: {}", tokenType, fingerprint, e.getMessage());
        return Mono.error(new AuthenticationServiceException(tokenType + " validation failed", e));
    }

    // Immutable token wrapper for safe handling
    private static class SafeToken {
        private final String token;
        private final String fingerprint;

        SafeToken(String token) {
            this.token = Objects.requireNonNull(token);
            this.fingerprint = token.substring(0, Math.min(5, token.length())) + "..." +
                    token.substring(Math.max(0, token.length() - 5));
        }

        String getToken() { return token; }
        String getFingerprint() { return fingerprint; }
    }

    public record TokenProcessingResult(
            String userId,
            String email,
            TokenType tokenType,
            Map<String, Object> claims,
            Collection<GrantedAuthority> authorities
    ) {}

    public enum TokenType { FIREBASE, CUSTOM_JWT }
}