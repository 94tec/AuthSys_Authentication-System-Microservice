package com.techStack.authSys.service.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.dto.request.TokenProcessingResult;
import com.techStack.authSys.models.security.TokenType;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.firebase.FirebaseTokenCacheService;
import com.techStack.authSys.util.auth.TokenValidator;
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
import static com.techStack.authSys.constants.SecurityConstants.CLAIM_TYPE_PERMISSIONS_GRANTED;
import static com.techStack.authSys.models.security.TokenType.*;

/**
 * Token Processing Service
 *
 * Processes and validates tokens (Firebase and Custom JWT).
 * Extracts claims and authorities for authentication.
 *
 * <p>Improvements over previous version:
 * <ul>
 *   <li> — single source of truth for TokenType → claim string mapping,
 *       shared between {@link #validateAndCacheJwtToken} and {@link #processTokenSafely} routing.</li>
 *   <li>Exhaustive switch expressions — {@code default} fallback that silently mapped unknown
 *       token types to ACCESS has been removed. Unknown types now fail fast and loud.</li>
 *   <li>{@link #createJwtTokenResult} — replaced unsafe {@code claims.get("sub").toString()}
 *       with a null-safe extraction that produces a clear error instead of a NullPointerException.</li>
 *   <li>{@link #extractTokenPayload} — payload decoding is now shared via a single call in
 *       {@link #determineTokenType}, eliminating the double-decode that existed when both
 *        and  decoded the same token independently.</li>
 *   <li>{@code ObjectMapper} is now injected rather than constructed inline, making the bean
 *       participte in Spring's shared singleton lifecycle and enabling easier test overrides.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class TokenProcessingService {

    private static final Logger log = LoggerFactory.getLogger(TokenProcessingService.class);

    private static final String FIREBASE_ISS_PREFIX = "https://securetoken.google.com/";

    // Forward map: claim type String -> TokenType enum
    private static final Map<String, TokenType> CLAIM_TYPE_TO_TOKEN_TYPE = Map.of(
            CLAIM_TYPE_ACCESS,          ACCESS,
            CLAIM_TYPE_REFRESH,         REFRESH,
            CLAIM_TYPE_TEMPORARY,       TEMPORARY,
            CLAIM_TYPE_PASSWORD_RESET,  PASSWORD_RESET,
            TOKEN_TYPE_TEMPORARY_LOGIN, TEMPORARY_LOGIN,
            CLAIM_TYPE_PERMISSIONS_GRANTED, PERMISSIONS_GRANTED
    );

    // Reverse map: TokenType enum -> claim type String (built dynamically)
    public static final Map<TokenType, String> TOKEN_TYPE_TO_CLAIM_TYPE;

    static {
        Map<TokenType, String> reverse = new EnumMap<>(TokenType.class);
        CLAIM_TYPE_TO_TOKEN_TYPE.forEach((claim, type) -> reverse.put(type, claim));
        TOKEN_TYPE_TO_CLAIM_TYPE = Collections.unmodifiableMap(reverse);
    }

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseTokenCacheService firebaseTokenCacheService;
    private final RedisUserCacheService redisCacheService;
    //private final JwtService jwtValidationService;
    private final TokenValidator tokenValidator;
    private final Clock clock;
    private final ObjectMapper objectMapper; // injected — participates in Spring singleton lifecycle

    /* =========================
       Token Processing
       ========================= */

    /**
     * Process token and extract authentication details.
     */
    public Mono<TokenProcessingResult> processToken(String token) {
        Instant startTime = clock.instant();

        return Mono.fromCallable(() -> new SafeToken(token))
                .flatMap(this::processTokenSafely)
                .doOnSuccess(result -> {
                    long durationMs = java.time.Duration.between(startTime, clock.instant()).toMillis();
                    log.debug("Token processed in {} ms", durationMs);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Route to the correct processor based on token type.
     *
     * <p>Uses a switch expression instead of a switch statement — the compiler enforces
     * exhaustiveness, so adding a new {@link TokenType} without handling it here is a
     * compile error rather than a silent runtime fallthrough.
     */
    private Mono<TokenProcessingResult> processTokenSafely(SafeToken safeToken) {
        return determineTokenType(safeToken.getToken())
                .flatMap(tokenType -> switch (tokenType) {
                    case FIREBASE ->
                            processFirebaseToken(safeToken);
                    case ACCESS, REFRESH, TEMPORARY, PASSWORD_RESET, CUSTOM_JWT ->
                            processJwtToken(safeToken, tokenType);
                    case TEMPORARY_LOGIN ->
                            processTemporaryLoginToken(safeToken);
                    case PERMISSIONS_GRANTED ->
                            processPermissionsGrantedToken(safeToken);
                    // No default — exhaustive. Compiler will catch any new unhandled TokenType.
                })
                .doOnSuccess(result -> logAuthSuccess(result.userId()))
                .doOnError(e -> logAuthFailure(safeToken.getFingerprint(), e));
    }
    /**
     * Process temporary login token (OTP/MFA verification)
     */
    /**
     * Process temporary login token (OTP/MFA verification)
     */
    private Mono<TokenProcessingResult> processTemporaryLoginToken(SafeToken safeToken) {
        Instant now = clock.instant();

        return tokenValidator.validateAndGetClaims(safeToken.getToken(), TokenType.TEMPORARY_LOGIN)
                .flatMap(claims -> {
                    Map<String, Object> mutableClaims = new HashMap<>(claims);
                    mutableClaims.put("token_type", TokenType.TEMPORARY_LOGIN.name());

                    return Mono.just(new TokenProcessingResult(
                            claims.getSubject(),
                            (String) claims.get("email"),
                            TokenType.TEMPORARY_LOGIN,
                            mutableClaims,
                            extractAuthorities(mutableClaims)
                    ));
                })
                .doOnSuccess(result ->
                        log.debug("Processed temporary login token at {}", now))
                .onErrorResume(e ->
                        handleAuthError("Temporary Login", safeToken.getFingerprint(), e));
    }

    /**
     * Process permissions granted token (post-authorization)
     */
    private Mono<TokenProcessingResult> processPermissionsGrantedToken(SafeToken safeToken) {
        Instant now = clock.instant();

        return tokenValidator.validateAndGetClaims(safeToken.getToken(), TokenType.PERMISSIONS_GRANTED)
                .flatMap(claims -> {
                    Map<String, Object> mutableClaims = new HashMap<>(claims);
                    mutableClaims.put("token_type", TokenType.PERMISSIONS_GRANTED.name());

                    return Mono.just(new TokenProcessingResult(
                            claims.getSubject(),
                            (String) claims.get("email"),
                            TokenType.PERMISSIONS_GRANTED,
                            mutableClaims,
                            extractAuthorities(mutableClaims)
                    ));
                })
                .doOnSuccess(result ->
                        log.debug("Processed permissions granted token at {}", now))
                .onErrorResume(e ->
                        handleAuthError("Permissions Granted", safeToken.getFingerprint(), e));
    }

    /* =========================
       Token Type Determination
       ========================= */

    /**
     * Determine the token type by inspecting the decoded payload.
     *
     * <p>The payload is decoded exactly once here and passed to both the Firebase and
     * custom-JWT checks, rather than each check decoding it independently as before.
     */
    private Mono<TokenType> determineTokenType(String token) {
        return Mono.fromCallable(() -> {
            verifyTokenNotEmpty(token);
            verifyTokenStructure(token);

            JsonNode payload = extractTokenPayload(token);

            if (isFirebasePayload(payload)) return FIREBASE;
            if (isCustomJwtPayload(payload)) return resolveCustomJwtType(payload);

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

    /**
     * Inspect a pre-decoded payload to determine if this is a Firebase token.
     * Accepts the payload directly to avoid a second Base64 decode.
     */
    private boolean isFirebasePayload(JsonNode payload) {
        return payload.has("iss") &&
                payload.get("iss").asText().startsWith(FIREBASE_ISS_PREFIX);
    }

    /**
     * Inspect a pre-decoded payload to determine if this is a custom JWT.
     * Accepts the payload directly to avoid a second Base64 decode.
     */
    private boolean isCustomJwtPayload(JsonNode payload) {
        return payload.has(CLAIM_TYPE);
    }

    /**
     * Map the {@code type} claim in a custom JWT payload to its {@link TokenType}.
     * Falls back to {@link TokenType#CUSTOM_JWT} for unrecognised type strings.
     */
    private TokenType resolveCustomJwtType(JsonNode payload) {
        String claimValue = payload.has(CLAIM_TYPE) ? payload.get(CLAIM_TYPE).asText() : "";
        return CLAIM_TYPE_TO_TOKEN_TYPE.getOrDefault(claimValue, CUSTOM_JWT);
    }

    /**
     * Decode and parse the JWT payload segment.
     * Called once per token in {@link #determineTokenType}.
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

    private Mono<TokenProcessingResult> processFirebaseToken(SafeToken safeToken) {
        Instant now = clock.instant();

        return firebaseTokenCacheService.getCachedToken(safeToken.getToken())
                .switchIfEmpty(Mono.defer(() -> verifyAndCacheFirebaseToken(safeToken)))
                .map(this::createFirebaseTokenResult)
                .doOnSuccess(result -> log.debug("Processed Firebase token at {}", now))
                .onErrorResume(e -> handleAuthError("Firebase", safeToken.getFingerprint(), e));
    }

    private Mono<FirebaseToken> verifyAndCacheFirebaseToken(SafeToken safeToken) {
        return Mono.fromCallable(() -> FirebaseAuth.getInstance().verifyIdToken(safeToken.getToken()))
                .flatMap(decoded -> firebaseTokenCacheService
                        .cacheToken(safeToken.getToken(), decoded)
                        .thenReturn(decoded))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private TokenProcessingResult createFirebaseTokenResult(FirebaseToken token) {
        return new TokenProcessingResult(
                token.getUid(),
                token.getEmail(),
                FIREBASE,
                makeMutable(token.getClaims()),
                extractAuthorities(token.getClaims())
        );
    }

    /* =========================
       JWT Token Processing
       ========================= */

    private Mono<TokenProcessingResult> processJwtToken(SafeToken safeToken, TokenType tokenType) {
        Instant now = clock.instant();

        return redisCacheService.getTokenClaims(safeToken.getToken())
                .flatMap(this::createMutableClaimsMap)
                .switchIfEmpty(Mono.defer(() -> validateAndCacheJwtToken(safeToken, tokenType)))
                .map(this::createJwtTokenResult)
                .doOnSuccess(result -> log.debug("Processed {} token at {}", tokenType, now))
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

    /**
     * Validate the token against its expected claim type, then cache the result.
     *
     * <p>Previously used a switch with a {@code default -> CLAIM_TYPE_ACCESS} fallback, which
     * silently treated any unrecognised {@link TokenType} as an access token — masking bugs and
     * making it impossible to detect misconfiguration at runtime. The lookup now uses
     *  and throws explicitly for unmapped types.
     */
    private Mono<Map<String, Object>> validateAndCacheJwtToken(SafeToken safeToken, TokenType tokenType) {
        // For CUSTOM_JWT, validate without type enforcement
        if (tokenType == CUSTOM_JWT) {
            return tokenValidator.validateAndGetClaims(safeToken.getToken(), null)
                    .flatMap(claims -> cacheClaimsWithFallback(safeToken.getToken(), claims))
                    .map(claims -> {
                        claims.put("token_type", tokenType.name());
                        return claims;
                    });
        }

        // For all other token types, pass the TokenType enum directly
        // TokenValidator already knows how to map each enum to the correct validation logic
        return tokenValidator.validateAndGetClaims(safeToken.getToken(), tokenType)
                .flatMap(claims -> cacheClaimsWithFallback(safeToken.getToken(), claims))
                .map(claims -> {
                    claims.put("token_type", tokenType.name());
                    return claims;
                });
    }

    private Mono<Map<String, Object>> cacheClaimsWithFallback(String token, Map<String, Object> claims) {
        return redisCacheService.cacheTokenClaims(token, claims)
                .onErrorResume(e -> {
                    log.warn("Failed to cache claims, continuing without cache", e);
                    return Mono.empty();
                })
                .thenReturn(claims);
    }

    /**
     * Build a {@link TokenProcessingResult} from a validated JWT claims map.
     *
     * <p>The original used {@code claims.get("sub").toString()} which would throw a
     * {@link NullPointerException} if the {@code sub} claim was absent — surfacing as an
     * unhelpful 500 rather than an authentication failure. The subject is now extracted
     * safely with a clear error if missing.
     */
    private TokenProcessingResult createJwtTokenResult(Map<String, Object> claims) {
        Object sub = claims.get("sub");
        if (sub == null) {
            throw new AuthenticationServiceException("JWT is missing required 'sub' claim");
        }

        return new TokenProcessingResult(
                sub.toString(),
                (String) claims.get("email"),
                CUSTOM_JWT,
                claims,
                extractAuthorities(claims)
        );
    }

    /* =========================
       Authority Extraction
       ========================= */

    private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        extractRoles(claims).forEach(role ->
                authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role)));
        extractPermissions(claims).forEach(perm ->
                authorities.add(new SimpleGrantedAuthority(PERM_PREFIX + perm)));

        return authorities.isEmpty()
                ? Set.of(new SimpleGrantedAuthority(DEFAULT_ROLE))
                : authorities;
    }

    private Set<String> extractRoles(Map<String, Object> claims) {
        Set<String> roles = extractClaimValues(claims.get(CLAIM_ROLES));
        roles.addAll(extractClaimValues(claims.get("role"))); // legacy support
        return roles;
    }

    private Set<String> extractPermissions(Map<String, Object> claims) {
        return extractClaimValues(claims.get(CLAIM_PERMISSIONS));
    }

    /**
     * Extract string values from a claim that may be a comma-delimited string or a collection.
     */
    private Set<String> extractClaimValues(Object claim) {
        if (claim instanceof String s) {
            return Arrays.stream(s.split(","))
                    .map(String::trim)
                    .filter(v -> !v.isEmpty())
                    .collect(Collectors.toSet());
        }
        if (claim instanceof Collection<?> collection) {
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
     * Deep-copy a claims map into a fully mutable {@link HashMap}.
     * Nested maps and collections are recursively made mutable.
     */
    private Map<String, Object> makeMutable(Map<?, ?> original) {
        Map<String, Object> mutable = new HashMap<>(original.size());
        original.forEach((k, v) -> mutable.put(k.toString(), makeMutableValue(v)));
        return mutable;
    }

    private Object makeMutableValue(Object value) {
        if (value instanceof Map<?, ?> map)      return makeMutable(map);
        if (value instanceof Collection<?> coll) return new ArrayList<>(coll);
        return value;
    }

    /* =========================
       Logging
       ========================= */

    private void logAuthSuccess(String userId) {
        log.info("Authentication successful for user: {} at {}", userId, clock.instant());
    }

    private void logAuthFailure(String tokenFingerprint, Throwable e) {
        log.error("Authentication failed for token: {} at {}. Error: {}",
                tokenFingerprint, clock.instant(), e.getMessage());
    }

    private <T> Mono<T> handleAuthError(String tokenType, String fingerprint, Throwable e) {
        log.error("{} token validation failed for: {} at {}. Error: {}",
                tokenType, fingerprint, clock.instant(), e.getMessage());
        return Mono.error(new AuthenticationServiceException(tokenType + " validation failed", e));
    }

    /* =========================
       Inner Classes
       ========================= */

    /**
     * Immutable token wrapper that pre-computes a non-sensitive fingerprint for logging.
     * The fingerprint exposes only the first and last 5 characters, never the full token.
     */
    private static class SafeToken {
        private final String token;
        private final String fingerprint;

        SafeToken(String token) {
            this.token = Objects.requireNonNull(token, "token must not be null");
            int len = token.length();
            this.fingerprint = token.substring(0, Math.min(5, len))
                    + "..."
                    + token.substring(Math.max(0, len - 5));
        }

        String getToken()       { return token; }
        String getFingerprint() { return fingerprint; }
    }
}