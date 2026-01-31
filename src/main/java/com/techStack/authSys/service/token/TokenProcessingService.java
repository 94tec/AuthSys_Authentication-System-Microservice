package com.techStack.authSys.service.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.firebase.FirebaseTokenCacheService;
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
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static com.techStack.authSys.constants.SecurityConstants.*;

/**
 * Token Processing Service
 *
 * Processes and validates tokens (Firebase and Custom JWT).
 * Extracts claims and authorities for authentication.
 */
@Service
@RequiredArgsConstructor
public class TokenProcessingService {

    private static final Logger log = LoggerFactory.getLogger(TokenProcessingService.class);

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseTokenCacheService firebaseTokenCacheService;
    private final RedisUserCacheService redisCacheService;
    private final JwtService jwtValidationService;
    private final Clock clock;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /* =========================
       Token Processing
       ========================= */

    /**
     * Process token and extract authentication details
     */
    public Mono<TokenProcessingResult> processToken(String token) {
        Instant startTime = clock.instant();

        return Mono.fromCallable(() -> new SafeToken(token))
                .flatMap(this::processTokenSafely)
                .doOnSuccess(result -> {
                    Instant endTime = clock.instant();
                    long durationMs = java.time.Duration.between(startTime, endTime).toMillis();
                    log.debug("Token processed in {} ms", durationMs);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Process token safely
     */
    private Mono<TokenProcessingResult> processTokenSafely(SafeToken safeToken) {
        return determineTokenType(safeToken.getToken())
                .flatMap(tokenType -> switch (tokenType) {
                    case FIREBASE -> processFirebaseToken(safeToken);
                    case CUSTOM_JWT -> processJwtToken(safeToken);
                })
                .doOnSuccess(result -> logAuthSuccess(result.userId()))
                .doOnError(e -> logAuthFailure(safeToken.getFingerprint(), e));
    }

    /* =========================
       Token Type Determination
       ========================= */

    /**
     * Determine token type (Firebase or Custom JWT)
     */
    private Mono<TokenType> determineTokenType(String token) {
        return Mono.fromCallable(() -> {
            verifyTokenNotEmpty(token);
            verifyTokenStructure(token);

            if (isFirebaseToken(token)) return TokenType.FIREBASE;
            if (isCustomJwt(token)) return TokenType.CUSTOM_JWT;

            throw new AuthenticationServiceException("Unsupported token type");
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Verify token is not empty
     */
    private void verifyTokenNotEmpty(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthenticationServiceException("Empty token");
        }
    }

    /**
     * Verify token structure (3 parts separated by dots)
     */
    private void verifyTokenStructure(String token) {
        if (token.split("\\.").length != 3) {
            throw new AuthenticationServiceException("Invalid JWT structure");
        }
    }

    /**
     * Check if token is Firebase token
     */
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

    /**
     * Check if token is custom JWT
     */
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

    /**
     * Extract token payload as JSON
     */
    private JsonNode extractTokenPayload(String token) throws Exception {
        String[] parts = token.split("\\.");
        String payloadJson = new String(
                Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8
        );
        return objectMapper.readTree(payloadJson);
    }

    /* =========================
       Firebase Token Processing
       ========================= */

    /**
     * Process Firebase token
     */
    private Mono<TokenProcessingResult> processFirebaseToken(SafeToken safeToken) {
        Instant now = clock.instant();

        return firebaseTokenCacheService.getCachedToken(safeToken.getToken())
                .switchIfEmpty(Mono.defer(() -> verifyAndCacheFirebaseToken(safeToken)))
                .map(this::createFirebaseTokenResult)
                .doOnSuccess(result ->
                        log.debug("Processed Firebase token at {}", now))
                .onErrorResume(e -> handleAuthError("Firebase", safeToken.getFingerprint(), e));
    }

    /**
     * Verify and cache Firebase token
     */
    private Mono<FirebaseToken> verifyAndCacheFirebaseToken(SafeToken safeToken) {
        return Mono.fromCallable(() -> FirebaseAuth.getInstance().verifyIdToken(safeToken.getToken()))
                .flatMap(decoded -> firebaseTokenCacheService.cacheToken(safeToken.getToken(), decoded)
                        .thenReturn(decoded))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Create Firebase token result
     */
    private TokenProcessingResult createFirebaseTokenResult(FirebaseToken token) {
        return new TokenProcessingResult(
                token.getUid(),
                token.getEmail(),
                TokenType.FIREBASE,
                makeMutable(token.getClaims()),
                extractAuthorities(token.getClaims())
        );
    }

    /* =========================
       JWT Token Processing
       ========================= */

    /**
     * Process custom JWT token
     */
    private Mono<TokenProcessingResult> processJwtToken(SafeToken safeToken) {
        Instant now = clock.instant();

        return redisCacheService.getTokenClaims(safeToken.getToken())
                .flatMap(this::createMutableClaimsMap)
                .switchIfEmpty(Mono.defer(() -> validateAndCacheJwtToken(safeToken)))
                .map(this::createJwtTokenResult)
                .doOnSuccess(result ->
                        log.debug("Processed JWT token at {}", now))
                .onErrorResume(e -> handleAuthError("JWT", safeToken.getFingerprint(), e));
    }

    /**
     * Create mutable claims map
     */
    private Mono<Map<String, Object>> createMutableClaimsMap(Object claims) {
        return Mono.fromCallable(() -> {
            if (!(claims instanceof Map)) {
                throw new AuthenticationServiceException("Invalid claims format");
            }
            return makeMutable((Map<?, ?>) claims);
        });
    }

    /**
     * Validate and cache JWT token
     */
    private Mono<Map<String, Object>> validateAndCacheJwtToken(SafeToken safeToken) {
        return jwtValidationService.validateToken(safeToken.getToken(), CLAIM_TYPE_ACCESS)
                .flatMap(claims -> cacheClaimsWithFallback(safeToken.getToken(), claims));
    }

    /**
     * Cache claims with fallback
     */
    private Mono<Map<String, Object>> cacheClaimsWithFallback(String token, Map<String, Object> claims) {
        return redisCacheService.cacheTokenClaims(token, claims)
                .onErrorResume(e -> {
                    log.warn("Failed to cache claims", e);
                    return Mono.empty(); // Continue with claims even if caching fails
                })
                .thenReturn(claims);
    }

    /**
     * Create JWT token result
     */
    private TokenProcessingResult createJwtTokenResult(Map<String, Object> claims) {
        return new TokenProcessingResult(
                claims.get("sub").toString(),
                (String) claims.get("email"),
                TokenType.CUSTOM_JWT,
                claims,
                extractAuthorities(claims)
        );
    }

    /* =========================
       Authority Extraction
       ========================= */

    /**
     * Extract authorities from claims
     */
    private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Extract roles
        extractRoles(claims).forEach(role ->
                authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role)));

        // Extract permissions
        extractPermissions(claims).forEach(perm ->
                authorities.add(new SimpleGrantedAuthority(PERM_PREFIX + perm)));

        return authorities.isEmpty() ?
                Set.of(new SimpleGrantedAuthority(DEFAULT_ROLE)) :
                authorities;
    }

    /**
     * Extract roles from claims
     */
    private Set<String> extractRoles(Map<String, Object> claims) {
        Set<String> roles = extractClaimValues(claims.get(CLAIM_ROLES));
        roles.addAll(extractClaimValues(claims.get("role"))); // Legacy support
        return roles;
    }

    /**
     * Extract permissions from claims
     */
    private Set<String> extractPermissions(Map<String, Object> claims) {
        return extractClaimValues(claims.get(CLAIM_PERMISSIONS));
    }

    /**
     * Extract claim values (handles strings and collections)
     */
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

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Make map mutable
     */
    private Map<String, Object> makeMutable(Map<?, ?> original) {
        Map<String, Object> mutable = new HashMap<>();
        original.forEach((k, v) -> mutable.put(k.toString(), makeMutableValue(v)));
        return mutable;
    }

    /**
     * Make value mutable
     */
    private Object makeMutableValue(Object value) {
        if (value instanceof Map<?, ?> map) return makeMutable(map);
        if (value instanceof Collection<?> coll) return new ArrayList<>(coll);
        return value;
    }

    /* =========================
       Logging
       ========================= */

    /**
     * Log authentication success
     */
    private void logAuthSuccess(String userId) {
        Instant now = clock.instant();
        log.info("Authentication successful for user: {} at {}", userId, now);
    }

    /**
     * Log authentication failure
     */
    private void logAuthFailure(String tokenFingerprint, Throwable e) {
        Instant now = clock.instant();
        log.error("Authentication failed for token: {} at {}. Error: {}",
                tokenFingerprint, now, e.getMessage());
    }

    /**
     * Handle authentication error
     */
    private <T> Mono<T> handleAuthError(String tokenType, String fingerprint, Throwable e) {
        Instant now = clock.instant();
        log.error("{} token validation failed for: {} at {}. Error: {}",
                tokenType, fingerprint, now, e.getMessage());
        return Mono.error(new AuthenticationServiceException(tokenType + " validation failed", e));
    }

    /* =========================
       Inner Classes
       ========================= */

    /**
     * Immutable token wrapper for safe handling
     */
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

    /**
     * Token type enum
     */
    public enum TokenType {
        FIREBASE,
        CUSTOM_JWT
    }
}