package com.techStack.authSys.service.token;

import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.config.security.JwtConfig;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.auth.*;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.EncryptionService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import com.techStack.authSys.util.firebase.FirestoreUtils;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.security.Key;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static com.techStack.authSys.constants.SecurityConstants.*;

/**
 * JWT Service
 *
 * Manages JWT token generation, validation, and lifecycle.
 * Uses Clock injection for all timestamp operations.
 *
 * Migration note — v1 → v2:
 *   All method signatures previously accepting Set<Permissions> or Set<String> converted
 *   from enum values now accept Set<String> directly — permission full names e.g.
 *   "portfolio:publish". The private toPermissionNames() helper that did
 *   Permissions::name mapping is removed since the input is already strings.
 *
 * Internal deduplication (unchanged from v1):
 *   - buildTemporaryToken    — shared builder for all scoped temporary tokens
 *   - extractUserIdForType   — shared extractor for temporary token types
 *   - buildAuditPayload      — shared audit log map builder
 *   - revokeTokenInFirestore — shared Firestore revocation writer
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final FirebaseAuth firebaseAuth;
    private final JwtConfig jwtConfig;
    private final Environment environment;
    private final EncryptionService encryptionService;
    private final Clock clock;

    // -------------------------------------------------------------------------
    // ACCESS TOKEN
    // -------------------------------------------------------------------------

    /**
     * Generate access token (simple — no request context available).
     * Passes the user's already-resolved string permissions directly.
     */
    public String generateAccessToken(User user) {
        return generateAccessToken(
                user,
                "unknown",
                "unknown",
                clock.instant(),
                new ArrayList<>(user.getAllPermissions())   // Convert Set → List
        );
    }

    /**
     * Generate access token (full version with request context).
     *
     * Fix from original: parameter was Set<Permissions> requiring .map(Enum::name).
     * Now accepts Set<String> directly — permission full names e.g. "portfolio:publish".
     *
     * @param user        the authenticated user
     * @param ipAddress   client IP for the ipAddress claim
     * @param userAgent   client user agent for the userAgent claim
     * @param issuedAt    token issue time (from Clock — testable)
     * @param permissions set of permission full name strings
     * @return signed JWT access token string
     */
    public String generateAccessToken(
            User user,
            String ipAddress,
            String userAgent,
            Instant issuedAt,
            List<String> permissions
    ) {
        Map<String, Object> claims = buildEnhancedClaims(
                user, ipAddress, userAgent, TOKEN_TYPE_ACCESS, permissions);

        return jwtConfig.jwtBuilder()
                .setClaims(claims)
                .setSubject(user.getId())
                .setIssuer(jwtConfig.getIssuer())
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(
                        issuedAt.plusSeconds(jwtConfig.getAccessTokenExpirationInSeconds())))
                .signWith(jwtConfig.accessTokenSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    // -------------------------------------------------------------------------
    // REFRESH TOKEN
    // -------------------------------------------------------------------------

    /**
     * Generate refresh token (simple — no request context available).
     */
    public String generateRefreshToken(String userId) {
        Instant now = clock.instant();
        String jti = UUID.randomUUID().toString();

        Map<String, Object> claims = new HashMap<>();
        claims.put("type",   TOKEN_TYPE_REFRESH);
        claims.put("userId", userId);
        claims.put("jti",    jti);

        return jwtConfig.refreshTokenJwtBuilder()
                .setClaims(claims)
                .setSubject(userId)
                .setIssuer(jwtConfig.getIssuer())
                .setId(jti)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(
                        now.plusSeconds(jwtConfig.getRefreshTokenExpirationInSeconds())))
                .signWith(jwtConfig.refreshTokenSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Generate refresh token (full version with request context).
     *
     * Fix from original: parameter was Set<Permissions>. Now Set<String>.
     *
     * @param permissions set of permission full name strings
     */
    public String generateRefreshToken(
            User user,
            String ipAddress,
            String userAgent,
            Instant issuedAt,
            List<String> permissions
    ) {
        String jti = UUID.randomUUID().toString();
        Map<String, Object> claims = buildEnhancedClaims(
                user, ipAddress, userAgent, TOKEN_TYPE_REFRESH, permissions);
        claims.put("jti", jti);

        return jwtConfig.refreshTokenJwtBuilder()
                .setClaims(claims)
                .setSubject(user.getId())
                .setIssuer(jwtConfig.getIssuer())
                .setId(jti)
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(
                        issuedAt.plusSeconds(jwtConfig.getRefreshTokenExpirationInSeconds())))
                .signWith(jwtConfig.refreshTokenSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    // -------------------------------------------------------------------------
    // TEMPORARY TOKENS
    // -------------------------------------------------------------------------

    /** Generate temporary token for first-time setup. Expiry: 30 minutes. */
    public String generateTemporaryToken(String userId) {
        return buildTemporaryToken(userId, TOKEN_TYPE_TEMPORARY_SETUP, "FIRST_TIME_SETUP", 1800);
    }

    /** Generate temporary token for login OTP verification. Expiry: 5 minutes. */
    public String generateTemporaryLoginToken(String userId) {
        return buildTemporaryToken(userId, TOKEN_TYPE_TEMPORARY_LOGIN, "LOGIN_OTP", 300);
    }

    private String buildTemporaryToken(
            String userId, String tokenType, String scope, long expirySeconds) {
        Instant now = clock.instant();
        Map<String, Object> claims = new HashMap<>();
        claims.put("type",   tokenType);
        claims.put("scope",  scope);
        claims.put("userId", userId);

        return jwtConfig.jwtBuilder()
                .setClaims(claims)
                .setSubject(userId)
                .setIssuer(jwtConfig.getIssuer())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(expirySeconds)))
                .signWith(jwtConfig.accessTokenSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    // -------------------------------------------------------------------------
    // TOKEN TYPE CHECKS
    // -------------------------------------------------------------------------

    public boolean isRefreshToken(String token) { return hasTokenType(token, TOKEN_TYPE_REFRESH); }
    public boolean isAccessToken(String token)  { return hasTokenType(token, TOKEN_TYPE_ACCESS);  }

    private boolean hasTokenType(String token, String expectedType) {
        try {
            String type = extractAllClaims(token).get("type", String.class);
            return expectedType.equals(type);
        } catch (Exception e) {
            log.debug("Token type check failed [expected={}]: {}", expectedType, e.getMessage());
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // TOKEN EXTRACTION
    // -------------------------------------------------------------------------

    public String extractUserIdFromTemporaryToken(String token) {
        return extractUserIdForType(token, TOKEN_TYPE_TEMPORARY_SETUP, "setup");
    }

    public String extractUserIdFromTemporaryLoginToken(String token) {
        return extractUserIdForType(token, TOKEN_TYPE_TEMPORARY_LOGIN, "login OTP");
    }

    private String extractUserIdForType(String token, String expectedType, String label) {
        try {
            Claims claims = extractAllClaims(token);
            String type = claims.get("type", String.class);
            if (!expectedType.equals(type)) {
                log.warn("Invalid token type for {}: expected={}, actual={}", label, expectedType, type);
                return null;
            }
            return claims.getSubject();
        } catch (Exception e) {
            log.error("Failed to extract user ID from {} token: {}", label, e.getMessage());
            return null;
        }
    }

    public Claims extractAllClaims(String token) {
        return jwtConfig.jwtParser()
                .parseClaimsJws(token)
                .getBody();
    }

    // -------------------------------------------------------------------------
    // TOKEN PAIR GENERATION
    // -------------------------------------------------------------------------

    /**
     * Generate access + refresh token pair (without expiry metadata).
     *
     * Fix from original: parameter was Set<Permissions>. Now Set<String>.
     */
    public Mono<TokenPair> generateTokenPair(
            User user, String ipAddress, String userAgent, List<String> permissions) {
        return generateTokenPairWithExpiry(user, ipAddress, userAgent, permissions)
                .map(c -> new TokenPair(c.getAccessToken(), c.getRefreshToken()));
    }

    /**
     * Generate access + refresh token pair with expiry timestamps included.
     *
     * Fix from original: parameter was Set<Permissions>. Now Set<String>.
     */
    public Mono<TokenComponentsWithExpiry> generateTokenPairWithExpiry(
            User user, String ipAddress, String userAgent, List<String> permissions) {
        Instant now = clock.instant();

        return verifyFirebaseUser(user.getId())
                .flatMap(__ -> generateTokenComponents(user, ipAddress, userAgent, now, permissions))
                .flatMap(components -> storeRefreshToken(components, now))
                .doOnSuccess(__ -> logTokenGenerationSuccess(user, ipAddress))
                .doOnError(e  -> logTokenGenerationFailure(user, ipAddress, e))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Build both token strings and calculate their expiry instants.
     *
     * Fix from original: parameter was Set<Permissions>. Now Set<String>.
     */
    public Mono<TokenComponentsWithExpiry> generateTokenComponents(
            User user, String ipAddress, String userAgent,
            Instant issuedAt, List<String> permissions) {
        return Mono.fromCallable(() -> {
                    String accessToken  = generateAccessToken(
                            user, ipAddress, userAgent, issuedAt, permissions);
                    String refreshToken = generateRefreshToken(
                            user, ipAddress, userAgent, issuedAt, permissions);

                    return TokenComponentsWithExpiry.builder()
                            .userId(user.getId())
                            .tokenPair(new TokenPair(accessToken, refreshToken))
                            .accessTokenExpiry(issuedAt.plusSeconds(
                                    jwtConfig.getAccessTokenExpirationInSeconds()))
                            .refreshTokenExpiry(issuedAt.plusSeconds(
                                    jwtConfig.getRefreshTokenExpirationInSeconds()))
                            .ipAddress(ipAddress)
                            .userAgent(userAgent)
                            .build();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.error("Token generation failed for user {}", user.getId(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Token generation failed"));
                });
    }

    // -------------------------------------------------------------------------
    // TOKEN STORAGE
    // -------------------------------------------------------------------------

    public Mono<TokenComponentsWithExpiry> storeRefreshToken(
            TokenComponentsWithExpiry components, Instant issuedAt) {
        if (components == null || components.getRefreshToken() == null) {
            return Mono.error(new IllegalArgumentException("Token components cannot be null"));
        }

        return validateRefreshToken(components.getRefreshToken(), components.getUserId())
                .flatMap(claims -> {
                    RefreshTokenRecord record = RefreshTokenRecord.builder()
                            .tokenId(claims.getId())
                            .userId(components.getUserId())
                            .tokenHash(encryptionService.hashToken(components.getRefreshToken()))
                            .ipAddress(components.getIpAddress())
                            .userAgent(components.getUserAgent())
                            .issuedAt(issuedAt)
                            .expiresAt(claims.getExpiration().toInstant())
                            .revoked(false)
                            .build();

                    return storeRefreshTokenRecord(record).thenReturn(components);
                })
                .onErrorResume(e -> handleStorageError(e, components.getUserId()))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Void> storeRefreshTokenRecord(RefreshTokenRecord record) {
        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(
                        firestore.collection(COLLECTION_REFRESH_TOKENS)
                                .document(record.getTokenId())
                                .set(record)))
                .timeout(Duration.ofSeconds(5))
                .doOnSuccess(__ -> log.info("Refresh token stored for user {}", record.getUserId()))
                .onErrorMap(e -> new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to store refresh token", e))
                .then();
    }

    // -------------------------------------------------------------------------
    // TOKEN VALIDATION
    // -------------------------------------------------------------------------

    public Mono<Claims> parseToken(String token) {
        return Mono.fromCallable(() -> {
                    try {
                        return Jwts.parserBuilder()
                                .setSigningKey(jwtConfig.accessTokenSecretKey())
                                .setAllowedClockSkewSeconds(60)
                                .build().parseClaimsJws(token).getBody();
                    } catch (JwtException e) {
                        return Jwts.parserBuilder()
                                .setSigningKey(jwtConfig.refreshTokenSecretKey())
                                .setAllowedClockSkewSeconds(60)
                                .build().parseClaimsJws(token).getBody();
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(e -> new CustomException(HttpStatus.UNAUTHORIZED,
                        "Failed to parse token: " + e.getMessage()));
    }

    public Mono<Claims> validateToken(String token, String expectedType) {
        Instant now = clock.instant();

        return Mono.fromCallable(() -> {
                    Key signingKey = TOKEN_TYPE_REFRESH.equals(expectedType)
                            ? jwtConfig.refreshTokenSecretKey()
                            : jwtConfig.accessTokenSecretKey();

                    JwtParserBuilder parser = Jwts.parserBuilder()
                            .setSigningKey(signingKey)
                            .setAllowedClockSkewSeconds(30)
                            .requireIssuer(jwtConfig.getIssuer());

                    if (expectedType != null) {
                        parser.require("type", expectedType);
                    }

                    Claims claims = parser.build().parseClaimsJws(token).getBody();

                    Date currentTime = Date.from(now);
                    if (claims.getExpiration().before(
                            new Date(currentTime.getTime() - TimeUnit.MINUTES.toMillis(5)))) {
                        throw new ExpiredJwtException(null, claims, "Token expired too long ago");
                    }

                    log.debug("Token valid for user: {}", claims.getSubject());
                    return claims;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(this::mapToSecurityException);
    }

    public Mono<Claims> validateRefreshToken(String token, String expectedUserId) {
        return validateRefreshToken(token)
                .flatMap(claims -> {
                    if (!expectedUserId.equals(claims.getSubject())) {
                        return Mono.error(
                                new JwtException("Token subject does not match user ID"));
                    }
                    return Mono.just(claims);
                });
    }

    public Mono<Claims> validateRefreshToken(String token) {
        return validateToken(token, TOKEN_TYPE_REFRESH);
    }

    public TokenValidationResult validateAccessToken(String token, String ipAddress) {
        if (StringUtils.isBlank(token)) {
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Authorization token is required");
        }

        Instant now = clock.instant();

        try {
            Claims claims = validateJwtStructure(token);
            checkTokenRevocationStatus(claims);
            validateTokenContext(claims, ipAddress);
            return buildValidationResult(claims, true, "Valid token");

        } catch (ExpiredJwtException e) {
            log.warn("Expired token for subject: {}", e.getClaims().getSubject());
            auditLogService.logSecurityEvent("TOKEN_VALIDATION_FAILURE",
                    e.getClaims().getSubject(),
                    buildAuditPayload("expired", ipAddress, now));
            return buildValidationResult(e.getClaims(), false, "Token expired");

        } catch (JwtException e) {
            log.warn("Invalid access token: {}", e.getMessage());
            auditLogService.logSecurityEvent("TOKEN_VALIDATION_FAILURE", "unknown",
                    buildAuditPayload("invalid", ipAddress, now, "error", e.getMessage()));
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid access token");
        }
    }

    private Claims validateJwtStructure(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(jwtConfig.accessTokenSecretKey())
                .setAllowedClockSkewSeconds(60)
                .requireIssuer(jwtConfig.getIssuer())
                .require("type", TOKEN_TYPE_ACCESS)
                .build().parseClaimsJws(token).getBody();
    }

    // -------------------------------------------------------------------------
    // TOKEN REFRESH
    // -------------------------------------------------------------------------

    /**
     * Fix from original: parameter was Set<Permissions>. Now Set<String>.
     */
    public Mono<TokenPair> refreshTokens(
            String refreshToken, String ipAddress, String userAgent, List<String> permissions) {
        if (StringUtils.isBlank(refreshToken)) {
            return Mono.error(new CustomException(
                    HttpStatus.BAD_REQUEST, "Refresh token is required"));
        }

        return Mono.defer(() -> validateRefreshToken(refreshToken))
                .flatMap(claims -> processValidRefreshToken(
                        claims, ipAddress, userAgent, permissions))
                .doOnSuccess(tokens -> logRefreshSuccess(tokens, ipAddress))
                .doOnError(e -> logRefreshFailure(e, ipAddress))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<TokenPair> processValidRefreshToken(
            Claims claims, String ipAddress, String userAgent, List<String> permissions) {
        return checkTokenRevocationStatus(claims.getId())
                .then(retrieveUserFromClaims(claims))
                .flatMap(user -> verifyTokenContext(claims, ipAddress, userAgent, user))
                .flatMap(user -> generateTokenPair(user, ipAddress, userAgent, permissions)
                        .timeout(Duration.ofSeconds(5))
                        .onErrorMap(e -> new CustomException(
                                HttpStatus.INTERNAL_SERVER_ERROR, "Failed to generate new tokens")))
                .flatMap(tokenPair -> revokeOldToken(claims.getId(), tokenPair)
                        .thenReturn(tokenPair));
    }

    // -------------------------------------------------------------------------
    // TOKEN REVOCATION
    // -------------------------------------------------------------------------

    public Mono<Void> revokeTokensForIp(String userId, String ipAddress, String revokedBy) {
        if (StringUtils.isBlank(ipAddress)) {
            return Mono.error(new IllegalArgumentException("IP address cannot be empty"));
        }
        return findActiveTokensByIp(userId, ipAddress)
                .flatMap(docs -> revokeTokenBatch(docs, revokedBy))
                .doOnSuccess(count -> logRevocationSuccess(ipAddress, count, revokedBy))
                .doOnError(e -> logRevocationFailure(ipAddress, e, revokedBy))
                .then();
    }

    private Mono<List<QueryDocumentSnapshot>> findActiveTokensByIp(
            String userId, String ipAddress) {
        return Mono.fromCallable(() ->
                        firestore.collection("users").document(userId)
                                .collection(COLLECTION_REFRESH_TOKENS)
                                .whereEqualTo("ipAddress", ipAddress)
                                .whereEqualTo("revoked", false)
                                .get())
                .flatMap(f -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(f)))
                .timeout(Duration.ofSeconds(5))
                .map(QuerySnapshot::getDocuments)
                .doOnNext(docs -> {
                    if (docs.isEmpty())
                        log.info("No active tokens for IP: {}", ipAddress);
                });
    }

    private Mono<Integer> revokeTokenBatch(
            List<QueryDocumentSnapshot> documents, String revokedBy) {
        if (documents.isEmpty()) return Mono.just(0);

        Instant now = clock.instant();
        return Mono.fromCallable(() -> {
                    WriteBatch batch = firestore.batch();
                    documents.forEach(doc -> batch.update(doc.getReference(),
                            Map.of("revoked", true, "revokedAt", now, "revokedBy", revokedBy)));
                    return batch.commit();
                })
                .flatMap(f -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(f)))
                .timeout(Duration.ofSeconds(10))
                .thenReturn(documents.size());
    }

    public Mono<Void> revokeRefreshToken(String tokenId, String revokedBy) {
        return revokeTokenInFirestore(
                firestore.collection(COLLECTION_REFRESH_TOKENS).document(tokenId),
                Map.of("revoked", true, "revokedAt", clock.instant(), "revokedBy", revokedBy),
                Duration.ofSeconds(5),
                tokenId
        );
    }

    private Mono<Void> revokeOldToken(String jti, TokenPair newTokens) {
        Map<String, Object> data = Map.of(
                "revokedAt",        clock.instant().toString(),
                "replacedBy",       newTokens.getRefreshToken(),
                "tokenType",        "REFRESH_TOKEN",
                "revocationReason", "TOKEN_REFRESHED"
        );

        return FirestoreUtils.apiFutureToMono(
                        firestore.collection(COLLECTION_REVOKED_TOKENS).document(jti).set(data))
                .doOnSuccess(__ -> log.debug("Old refresh token revoked: {}", jti))
                .onErrorResume(e -> {
                    log.warn("Non-critical: could not revoke old token {}, continuing", jti);
                    return Mono.empty();
                }).then();
    }

    private Mono<Void> revokeTokenInFirestore(
            DocumentReference ref, Map<String, Object> updates,
            Duration timeout, String tokenId) {
        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(ref.update(updates)))
                .timeout(timeout)
                .doOnSuccess(__ -> log.info("Token revoked: {}", tokenId))
                .doOnError(e -> log.error("Failed to revoke token {}: {}", tokenId, e.getMessage()))
                .then();
    }

    public Mono<Boolean> isRefreshTokenRevoked(String tokenId) {
        return Mono.fromCallable(() ->
                        firestore.collection(COLLECTION_REFRESH_TOKENS).document(tokenId).get())
                .flatMap(f -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(f)))
                .timeout(Duration.ofSeconds(3))
                .map(doc -> doc.exists() && Boolean.TRUE.equals(doc.getBoolean("revoked")))
                .onErrorResume(e -> {
                    log.error("Failed to check token revocation status", e);
                    return Mono.just(true); // fail-secure
                });
    }

    // -------------------------------------------------------------------------
    // EMAIL VERIFICATION TOKENS
    // -------------------------------------------------------------------------

    public Mono<String> generateEmailVerificationToken(
            String userId, String email, String ipAddress) {
        if (StringUtils.isBlank(userId))    return Mono.error(
                new IllegalArgumentException("User ID cannot be empty"));
        if (StringUtils.isBlank(email))     return Mono.error(
                new IllegalArgumentException("Email cannot be empty"));
        if (StringUtils.isBlank(ipAddress)) return Mono.error(
                new IllegalArgumentException("IP address cannot be empty"));

        return Mono.fromCallable(() -> buildEmailVerificationJwt(
                        email, buildEmailVerificationClaims(userId, email, ipAddress)))
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(Duration.ofSeconds(2))
                .doOnSuccess(__ -> log.info(
                        "Generated email verification token for {}", email))
                .doOnError(e -> log.error(
                        "Failed to generate email verification token", e));
    }

    private Map<String, Object> buildEmailVerificationClaims(
            String userId, String email, String ipAddress) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId",       userId);
        claims.put("email",        email);
        claims.put("ipAddress",    ipAddress);
        claims.put("type",         TOKEN_TYPE_EMAIL_VERIFICATION);
        claims.put("tokenVersion", 1);
        claims.put("generatedAt",  clock.instant().getEpochSecond());
        return Collections.unmodifiableMap(claims);
    }

    private String buildEmailVerificationJwt(String email, Map<String, Object> claims) {
        Instant now = clock.instant();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuer(jwtConfig.getIssuer())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(
                        jwtConfig.getEmailVerificationExpirationInSeconds())))
                .signWith(jwtConfig.accessTokenSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public Mono<TokenClaims> verifyEmailVerificationToken(String token) {
        if (StringUtils.isBlank(token)) {
            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Token cannot be empty"));
        }
        return validateToken(token, TOKEN_TYPE_EMAIL_VERIFICATION)
                .flatMap(this::validateEmailVerificationClaims)
                .map(this::buildTokenClaims)
                .doOnSuccess(c -> log.info("Verified email token for {}", c.email()))
                .doOnError(e -> log.warn("Email verification failed: {}", e.getMessage()))
                .onErrorResume(this::handleEmailVerificationError);
    }

    private Mono<Claims> validateEmailVerificationClaims(Claims claims) {
        return Mono.just(claims)
                .filter(c -> TOKEN_TYPE_EMAIL_VERIFICATION.equals(c.get("type")))
                .switchIfEmpty(Mono.error(new CustomException(
                        HttpStatus.UNAUTHORIZED, "Invalid token type, expected email verification")))
                .filter(c -> StringUtils.isNotBlank(c.getSubject()))
                .switchIfEmpty(Mono.error(new CustomException(
                        HttpStatus.UNAUTHORIZED, "Missing email in token")));
    }

    private TokenClaims buildTokenClaims(Claims claims) {
        return TokenClaims.builder()
                .userId(claims.get("userId", String.class))
                .email(claims.getSubject())
                .ipAddress(claims.get("ipAddress", String.class))
                .expiration(claims.getExpiration())
                .tokenVersion(claims.get("tokenVersion", Integer.class))
                .issuedAt(claims.getIssuedAt().toInstant())
                .build();
    }

    private Mono<TokenClaims> handleEmailVerificationError(Throwable e) {
        if (e instanceof ExpiredJwtException)   return Mono.error(
                new CustomException(HttpStatus.UNAUTHORIZED, "Token has expired"));
        if (e instanceof SignatureException)    return Mono.error(
                new CustomException(HttpStatus.UNAUTHORIZED, "Invalid token signature"));
        if (e instanceof MalformedJwtException) return Mono.error(
                new CustomException(HttpStatus.BAD_REQUEST, "Malformed token"));
        if (e instanceof CustomException ce)    return Mono.error(ce);
        log.error("Unexpected token error: {}", e.getMessage(), e);
        return Mono.error(new CustomException(
                HttpStatus.INTERNAL_SERVER_ERROR, "Token processing failed"));
    }

    // -------------------------------------------------------------------------
    // TOKEN EXPIRY
    // -------------------------------------------------------------------------

    public Mono<Instant> getRefreshTokenExpiry(String token) {
        return getTokenExpiry(token, TOKEN_TYPE_REFRESH);
    }

    public Mono<Instant> getAccessTokenExpiry(String token) {
        return getTokenExpiry(token, TOKEN_TYPE_ACCESS);
    }

    public Mono<Instant> getTokenExpiry(String token, String tokenType) {
        return validateToken(token, tokenType)
                .map(c -> c.getExpiration().toInstant())
                .onErrorMap(e -> new CustomException(HttpStatus.UNAUTHORIZED,
                        String.format("Invalid %s token: %s", tokenType, e.getMessage())));
    }

    // -------------------------------------------------------------------------
    // CLAIM EXTRACTION
    // -------------------------------------------------------------------------

    public Mono<Claims> getClaimsFromToken(String token) {
        if (StringUtils.isBlank(token)) {
            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Token cannot be empty"));
        }
        return parseToken(token)
                .timeout(Duration.ofSeconds(2))
                .doOnSuccess(__ -> log.debug("Claims extracted successfully"))
                .doOnError(e -> log.warn("Failed to extract claims: {}", e.getMessage()))
                .onErrorMap(this::mapToSecurityException);
    }

    public Mono<String> getUserIdFromToken(String token) {
        return getClaimsFromToken(token)
                .map(Claims::getSubject)
                .switchIfEmpty(Mono.error(new CustomException(
                        HttpStatus.UNAUTHORIZED, "Missing subject claim")));
    }

    public Mono<String> getEmailFromToken(String token) {
        return getClaimsFromToken(token).flatMap(claims -> {
            String email = claims.get("email", String.class);
            return StringUtils.isNotBlank(email)
                    ? Mono.just(email)
                    : Mono.error(new CustomException(
                    HttpStatus.UNAUTHORIZED, "Missing email claim"));
        });
    }

    public Mono<List<String>> getRolesFromToken(String token) {
        return getClaimsFromToken(token).map(claims -> {
            List<String> roles = claims.get("roles", List.class);
            return roles != null ? roles : Collections.emptyList();
        });
    }

    public Mono<Set<String>> getPermissionsFromToken(String token) {
        return getClaimsFromToken(token).map(claims -> {
            List<String> perms = claims.get("permissions", List.class);
            return perms != null ? new HashSet<>(perms) : Collections.emptySet();
        });
    }

    // -------------------------------------------------------------------------
    // FIREBASE HELPERS
    // -------------------------------------------------------------------------

    public Mono<String> verifyFirebaseUser(String userId) {
        return Mono.fromCallable(() -> {
                    UserRecord record = firebaseAuth.getUser(userId);
                    log.info("Firebase verification succeeded for user {}", userId);
                    return record.getUid();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.error("Firebase user verification failed for user {}", userId, e);
                    return Mono.error(new CustomException(
                            HttpStatus.NOT_FOUND, "User not found in Firebase"));
                });
    }

    // -------------------------------------------------------------------------
    // REVOCATION CHECK HELPERS
    // -------------------------------------------------------------------------

    private Mono<Void> checkTokenRevocationStatus(String jti) {
        return Mono.fromCallable(() ->
                        firestore.collection(COLLECTION_REVOKED_TOKENS).document(jti)
                                .get().get(2, TimeUnit.SECONDS))
                .flatMap(doc -> doc.exists()
                        ? Mono.error(new CustomException(
                        HttpStatus.UNAUTHORIZED, "Refresh token has been revoked"))
                        : Mono.empty())
                .onErrorResume(e -> {
                    log.error("Error checking token revocation status", e);
                    return Mono.error(new CustomException(
                            HttpStatus.UNAUTHORIZED, "Unable to verify token status"));
                }).then();
    }

    private void checkTokenRevocationStatus(Claims claims) {
        if (isTokenRevoked(claims.getId())) {
            log.warn("Attempt to use revoked token: {}", claims.getId());
            throw new JwtException("Token has been revoked");
        }
    }

    private boolean isTokenRevoked(String jti) {
        try {
            return firestore.collection(COLLECTION_REVOKED_TOKENS)
                    .document(jti).get().get(2, TimeUnit.SECONDS).exists();
        } catch (Exception e) {
            log.error("Error checking token revocation status", e);
            return true; // fail-secure
        }
    }

    // -------------------------------------------------------------------------
    // USER RETRIEVAL
    // -------------------------------------------------------------------------

    /**
     * Reads a UserDocument from Firestore and maps the fields needed for token
     * context validation into a domain User object.
     *
     * Fix from original: previously called doc.toObject(User.class) which fails
     * because Spring Data Firestore rejects the dual-annotated User class with
     * complex field types. Now reads via UserDocument (Firestore-safe types only)
     * and builds a thin domain User from the deserialized document.
     */
    private Mono<User> retrieveUserFromClaims(Claims claims) {
        return Mono.fromCallable(() -> {
                    String userId = claims.getSubject();
                    if (StringUtils.isBlank(userId)) {
                        throw new CustomException(
                                HttpStatus.UNAUTHORIZED, "Invalid token: no subject");
                    }

                    DocumentSnapshot snapshot = firestore.collection("users")
                            .document(userId).get().get(2, TimeUnit.SECONDS);

                    if (!snapshot.exists()) {
                        throw new CustomException(HttpStatus.NOT_FOUND, "User not found");
                    }

                    // Deserialize via UserDocument — Firestore-safe types, no Spring Data rejection
                    com.techStack.authSys.models.user.UserDocument userDoc =
                            snapshot.toObject(com.techStack.authSys.models.user.UserDocument.class);

                    if (userDoc == null) {
                        throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                                "Failed to deserialize user document for uid: " + userId);
                    }

                    // Build a thin domain User with only the fields needed for token validation
                    return User.builder()
                            .id(userDoc.getId())
                            .firebaseUid(userDoc.getId())
                            .email(userDoc.getEmail())
                            .roleNames(userDoc.getRoleNames() != null
                                    ? userDoc.getRoleNames() : List.of())
                            .firstName(userDoc.getFirstName())
                            .lastName(userDoc.getLastName())
                            .mfaRequired(userDoc.isMfaRequired())
                            .build();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(e -> e instanceof CustomException ? e :
                        new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                                "Failed to retrieve user", e));
    }

    // -------------------------------------------------------------------------
    // TOKEN CONTEXT VALIDATION
    // -------------------------------------------------------------------------

    private Mono<User> verifyTokenContext(
            Claims claims, String ipAddress, String userAgent, User user) {
        return Mono.fromCallable(() -> {
            String tokenIp        = claims.get("ipAddress", String.class);
            String tokenUserAgent = claims.get("userAgent",  String.class);

            if (!shouldEnforceIpValidation()
                    && !StringUtils.equals(tokenIp, ipAddress)) {
                log.warn("IP address changed from {} to {}", tokenIp, ipAddress);
                throw new CustomException(
                        HttpStatus.UNAUTHORIZED, "Token context invalid - IP mismatch");
            }
            if (!StringUtils.equals(tokenUserAgent, userAgent)) {
                log.warn("User-Agent changed from {} to {}", tokenUserAgent, userAgent);
                throw new CustomException(
                        HttpStatus.UNAUTHORIZED, "Token context invalid - User-Agent mismatch");
            }
            return user;
        });
    }

    private void validateTokenContext(Claims claims, String currentIp) {
        if (shouldEnforceIpValidation()) return;
        String tokenIp = claims.get("ipAddress", String.class);
        if (!StringUtils.equals(tokenIp, currentIp)) {
            log.warn("IP mismatch: token [{}], current [{}]", tokenIp, currentIp);
            throw new JwtException("Token context invalid - IP mismatch");
        }
    }

    private boolean shouldEnforceIpValidation() {
        return environment.getProperty(
                "security.ip-validation.enabled", Boolean.class, true);
    }

    // -------------------------------------------------------------------------
    // RESULT / ERROR BUILDERS
    // -------------------------------------------------------------------------

    private TokenValidationResult buildValidationResult(
            Claims claims, boolean valid, String message) {
        return TokenValidationResult.builder()
                .subject(claims.getSubject())
                .userId(claims.get("userId", String.class))
                .email(claims.get("email", String.class))
                .roles(claims.get("roles", List.class))
                .permissions(claims.get("permissions", List.class))
                .issuedAt(claims.getIssuedAt().toInstant())
                .expiration(claims.getExpiration().toInstant())
                .valid(valid)
                .message(message)
                .mfaEnabled(claims.get("mfaEnabled", Boolean.class))
                .build();
    }

    private Mono<TokenComponentsWithExpiry> handleStorageError(Throwable e, String userId) {
        log.error("Failed to store refresh token for user {}", userId, e);
        if (e instanceof TimeoutException)   return Mono.error(new CustomException(
                HttpStatus.REQUEST_TIMEOUT,    "Refresh token storage timed out"));
        if (e instanceof JwtException)       return Mono.error(new CustomException(
                HttpStatus.BAD_REQUEST,        "Invalid refresh token: " + e.getMessage()));
        if (e instanceof FirestoreException) return Mono.error(new CustomException(
                HttpStatus.SERVICE_UNAVAILABLE, "Database unavailable for token storage"));
        return Mono.error(new CustomException(
                HttpStatus.INTERNAL_SERVER_ERROR, "Failed to store refresh token"));
    }

    public CustomException mapToSecurityException(Throwable e) {
        if (e instanceof ExpiredJwtException) return new CustomException(
                HttpStatus.UNAUTHORIZED,             "Token expired");
        if (e instanceof JwtException)        return new CustomException(
                HttpStatus.UNAUTHORIZED,             "Invalid token");
        if (e instanceof TimeoutException)    return new CustomException(
                HttpStatus.REQUEST_TIMEOUT,          "Token validation timeout");
        return new CustomException(
                HttpStatus.INTERNAL_SERVER_ERROR,    "Token processing failed");
    }

    public Mono<Boolean> isTokenValid(String token) {
        return getClaimsFromToken(token)
                .map(__ -> true)
                .onErrorResume(e -> Mono.just(false));
    }

    // -------------------------------------------------------------------------
    // SHARED PRIVATE UTILITIES
    // -------------------------------------------------------------------------

    /**
     * Build the base enhanced claims map shared by access and refresh token builders.
     *
     * Fix from original: previously called toPermissionNames(Set<Permissions>) to convert
     * enum values to strings. permissions is now already Set<String> — passed through directly.
     */
    private Map<String, Object> buildEnhancedClaims(
            User user, String ipAddress, String userAgent,
            String tokenType, List<String> permissions) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type",          tokenType);
        claims.put("userId",        user.getId());
        claims.put("email",         user.getEmail());
        claims.put("roles",         user.getRoleNames());
        claims.put("permissions",   new ArrayList<>(permissions)); // List for JSON serialization
        claims.put("ipAddress",     ipAddress);
        claims.put("userAgent",     userAgent);
        claims.put("emailVerified", user.isEmailVerified());
        claims.put("phoneVerified", user.isPhoneVerified());
        return claims;
    }

    private String buildAuditPayload(
            String reason, String ip, Instant timestamp, Object... extras) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("reason",    reason);
        payload.put("ip",        ip);
        payload.put("timestamp", timestamp);
        for (int i = 0; i + 1 < extras.length; i += 2) {
            payload.put(extras[i].toString(), extras[i + 1]);
        }
        return payload.toString();
    }

    // -------------------------------------------------------------------------
    // LOGGING
    // -------------------------------------------------------------------------

    public void logTokenGenerationSuccess(User user, String ipAddress) {
        Instant now = clock.instant();
        log.info("Tokens generated for user {} from IP {}", user.getId(), ipAddress);
        auditLogService.logSecurityEvent("TOKEN_GENERATION", user.getId(),
                buildAuditPayload("success", ipAddress, now));
    }

    public void logTokenGenerationFailure(User user, String ipAddress, Throwable e) {
        Instant now = clock.instant();
        log.error("Token generation failed for user {} from IP {}", user.getId(), ipAddress, e);
        auditLogService.logSecurityEvent("TOKEN_GENERATION_FAILURE", user.getId(),
                buildAuditPayload("failed", ipAddress, now, "error", e.getMessage()));
    }

    private void logRefreshSuccess(TokenPair tokens, String ipAddress) {
        Instant now = clock.instant();
        log.info("Tokens refreshed for IP {}", ipAddress);
        String subject = tokens.getAccessToken().substring(
                0, Math.min(10, tokens.getAccessToken().length())) + "...";
        auditLogService.logSecurityEvent("TOKEN_REFRESH", subject,
                buildAuditPayload("success", ipAddress, now));
    }

    private void logRefreshFailure(Throwable e, String ipAddress) {
        Instant now = clock.instant();
        log.error("Token refresh failed for IP {}", ipAddress, e);
        auditLogService.logSecurityEvent("TOKEN_REFRESH_FAILURE", ipAddress,
                buildAuditPayload("failed", ipAddress, now,
                        "error", e.getMessage(),
                        "type", e instanceof CustomException ? "validation" : "system"));
    }

    private void logRevocationSuccess(String ipAddress, int count, String revokedBy) {
        log.info("Revoked {} tokens for IP {}", count, ipAddress);
        auditLogService.logSecurityEvent("TOKEN_REVOCATION", ipAddress,
                buildAuditPayload("blacklisted_ip", ipAddress, clock.instant(),
                        "count", count, "initiator", revokedBy));
    }

    private void logRevocationFailure(String ipAddress, Throwable e, String revokedBy) {
        log.error("Failed to revoke tokens for IP {}", ipAddress, e);
        auditLogService.logSecurityEvent("TOKEN_REVOCATION_FAILURE", ipAddress,
                buildAuditPayload("failed", ipAddress, clock.instant(),
                        "error", e.getMessage(), "initiator", revokedBy));
    }
}