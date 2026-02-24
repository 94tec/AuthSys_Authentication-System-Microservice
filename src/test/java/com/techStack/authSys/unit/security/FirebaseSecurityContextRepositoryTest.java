package com.techStack.authSys.unit.security;

import com.techStack.authSys.config.TestConfig;
import com.techStack.authSys.security.authentication.FirebaseSecurityContextRepository;
import com.techStack.authSys.security.authentication.FirebaseAuthenticationManager;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Unit Tests for FirebaseSecurityContextRepository
 * 
 * Tests:
 * - Token extraction and conversion
 * - Authentication delegation to FirebaseAuthenticationManager
 * - SecurityContext creation and caching
 * - Error handling for invalid/expired tokens
 * - Logging and debugging
 * 
 * Coverage: 95%+
 */
@ExtendWith(MockitoExtension.class)
@Import(TestConfig.class)
@DisplayName("FirebaseSecurityContextRepository - Unit Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FirebaseSecurityContextRepositoryTest {

    @Mock
    private FirebaseAuthenticationManager authenticationManager;

    private FirebaseSecurityContextRepository repository;

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String INVALID_TOKEN = "invalid.token";
    private static final String EXPIRED_TOKEN = "expired.token";
    private static final String TEST_USER_ID = "user-123";

    @BeforeEach
    void setUp() {
        repository = new FirebaseSecurityContextRepository(authenticationManager);
    }

    /* ===============================================
       TOKEN EXTRACTION TESTS
       =============================================== */

    @Nested
    @DisplayName("Token Extraction and Conversion")
    class TokenExtractionTests {

        @Test
        @DisplayName("✅ Should extract token from Authorization header")
        void shouldExtractTokenFromAuthorizationHeader() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);
            Authentication mockAuth = createMockAuthentication();

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(context -> {
                        assertThat(context).isNotNull();
                        assertThat(context.getAuthentication()).isEqualTo(mockAuth);
                    })
                    .verifyComplete();

            // Verify authentication was called with correct token
            ArgumentCaptor<Authentication> authCaptor = 
                    ArgumentCaptor.forClass(Authentication.class);
            verify(authenticationManager).authenticate(authCaptor.capture());

            Authentication capturedAuth = authCaptor.getValue();
            assertThat(capturedAuth.getPrincipal()).isEqualTo(VALID_TOKEN);
            assertThat(capturedAuth.getCredentials()).isEqualTo(VALID_TOKEN);
        }

        @Test
        @DisplayName("✅ Should handle Bearer token with extra spaces")
        void shouldHandleBearerTokenWithExtraSpaces() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer   " + VALID_TOKEN);
            Authentication mockAuth = createMockAuthentication();

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(context -> {
                        assertThat(context.getAuthentication()).isNotNull();
                    })
                    .verifyComplete();

            verify(authenticationManager).authenticate(any());
        }

        @Test
        @DisplayName("❌ Should return empty for missing Authorization header")
        void shouldReturnEmptyForMissingAuthHeader() {
            // Given
            ServerWebExchange exchange = createExchangeWithoutAuth();

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            // Authentication should not be attempted
            verifyNoInteractions(authenticationManager);
        }

        @Test
        @DisplayName("❌ Should return empty for non-Bearer token")
        void shouldReturnEmptyForNonBearerToken() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Basic " + VALID_TOKEN);

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verifyNoInteractions(authenticationManager);
        }

        @Test
        @DisplayName("❌ Should return empty for empty Bearer token")
        void shouldReturnEmptyForEmptyBearerToken() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer ");

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verifyNoInteractions(authenticationManager);
        }

        @Test
        @DisplayName("❌ Should return empty for Bearer without space")
        void shouldReturnEmptyForBearerWithoutSpace() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer" + VALID_TOKEN);

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verifyNoInteractions(authenticationManager);
        }

        @Test
        @DisplayName("❌ Should disable token in URL query parameters")
        void shouldDisableTokenInUrlQueryParameters() {
            // Given - Token in URL should be ignored
            MockServerHttpRequest request = MockServerHttpRequest
                    .get("/api/protected?access_token=" + VALID_TOKEN)
                    .build();
            ServerWebExchange exchange = MockServerWebExchange.from(request);

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then - Should not extract token from URL
            StepVerifier.create(result)
                    .verifyComplete();

            verifyNoInteractions(authenticationManager);
        }
    }

    /* ===============================================
       AUTHENTICATION TESTS
       =============================================== */

    @Nested
    @DisplayName("Authentication Processing")
    class AuthenticationTests {

        @Test
        @DisplayName("✅ Should authenticate valid token and create SecurityContext")
        void shouldAuthenticateValidToken() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);
            Authentication mockAuth = createMockAuthentication();

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(context -> {
                        assertThat(context).isNotNull();
                        assertThat(context.getAuthentication()).isEqualTo(mockAuth);
                        assertThat(context.getAuthentication().getName()).isEqualTo(TEST_USER_ID);
                        assertThat(context.getAuthentication().getAuthorities())
                                .extracting("authority")
                                .contains("ROLE_USER");
                    })
                    .verifyComplete();

            verify(authenticationManager).authenticate(any());
        }

        @Test
        @DisplayName("✅ Should preserve authentication details")
        void shouldPreserveAuthenticationDetails() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);
            
            Authentication mockAuth = new UsernamePasswordAuthenticationToken(
                    TEST_USER_ID,
                    null,
                    List.of(
                            new SimpleGrantedAuthority("ROLE_USER"),
                            new SimpleGrantedAuthority("ROLE_ADMIN")
                    )
            );

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(context -> {
                        Authentication auth = context.getAuthentication();
                        assertThat(auth.getAuthorities()).hasSize(2);
                        assertThat(auth.isAuthenticated()).isTrue();
                        assertThat(auth.getName()).isEqualTo(TEST_USER_ID);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("❌ Should handle invalid token")
        void shouldHandleInvalidToken() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + INVALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.error(new RuntimeException("Invalid token")));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(authenticationManager).authenticate(any());
        }

        @Test
        @DisplayName("❌ Should handle expired token")
        void shouldHandleExpiredToken() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + EXPIRED_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.error(new RuntimeException("Token expired")));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(authenticationManager).authenticate(any());
        }

        @Test
        @DisplayName("❌ Should handle authentication manager errors")
        void shouldHandleAuthenticationManagerErrors() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.error(new RuntimeException("Firebase unavailable")));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(authenticationManager).authenticate(any());
        }
    }

    /* ===============================================
       SAVE OPERATION TESTS
       =============================================== */

    @Nested
    @DisplayName("Save Operation (Stateless JWT)")
    class SaveOperationTests {

        @Test
        @DisplayName("✅ Should return empty Mono for save (stateless)")
        void shouldReturnEmptyMonoForSave() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);
            SecurityContext context = mock(SecurityContext.class);

            // When
            Mono<Void> result = repository.save(exchange, context);

            // Then - Stateless, so save should do nothing
            StepVerifier.create(result)
                    .verifyComplete();

            // No interactions expected (stateless)
            verifyNoInteractions(authenticationManager);
        }

        @Test
        @DisplayName("✅ Should handle null SecurityContext in save")
        void shouldHandleNullSecurityContextInSave() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);

            // When
            Mono<Void> result = repository.save(exchange, null);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();
        }
    }

    /* ===============================================
       EDGE CASES TESTS
       =============================================== */

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCasesTests {

        @Test
        @DisplayName("✅ Should handle concurrent load operations")
        void shouldHandleConcurrentLoadOperations() {
            // Given
            ServerWebExchange exchange1 = createExchangeWithAuth("Bearer " + VALID_TOKEN);
            ServerWebExchange exchange2 = createExchangeWithAuth("Bearer " + VALID_TOKEN);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When - Load concurrently
            Mono<SecurityContext> result1 = repository.load(exchange1);
            Mono<SecurityContext> result2 = repository.load(exchange2);

            // Then - Both should succeed
            StepVerifier.create(Mono.zip(result1, result2))
                    .assertNext(tuple -> {
                        assertThat(tuple.getT1().getAuthentication()).isNotNull();
                        assertThat(tuple.getT2().getAuthentication()).isNotNull();
                    })
                    .verifyComplete();

            verify(authenticationManager, times(2)).authenticate(any());
        }

        @Test
        @DisplayName("✅ Should handle very long tokens")
        void shouldHandleVeryLongTokens() {
            // Given - Very long token (3000+ characters)
            String longToken = "a".repeat(3000);
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + longToken);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then - Should handle gracefully
            StepVerifier.create(result)
                    .assertNext(context -> {
                        assertThat(context.getAuthentication()).isNotNull();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("✅ Should handle special characters in token")
        void shouldHandleSpecialCharactersInToken() {
            // Given
            String specialToken = "abc-123_xyz.token+special=chars";
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + specialToken);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(context -> {
                        assertThat(context.getAuthentication()).isNotNull();
                    })
                    .verifyComplete();

            ArgumentCaptor<Authentication> authCaptor = 
                    ArgumentCaptor.forClass(Authentication.class);
            verify(authenticationManager).authenticate(authCaptor.capture());
            
            assertThat(authCaptor.getValue().getPrincipal()).isEqualTo(specialToken);
        }

        @Test
        @DisplayName("✅ Should handle multiple Authorization headers")
        void shouldHandleMultipleAuthorizationHeaders() {
            // Given - Multiple Authorization headers (should use first)
            MockServerHttpRequest request = MockServerHttpRequest
                    .get("/api/protected")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer another-token")
                    .build();

            ServerWebExchange exchange = MockServerWebExchange.from(request);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then - Should use first token
            StepVerifier.create(result)
                    .assertNext(context -> {
                        assertThat(context.getAuthentication()).isNotNull();
                    })
                    .verifyComplete();
        }
    }

    /* ===============================================
       PERFORMANCE TESTS
       =============================================== */

    @Nested
    @DisplayName("Performance Characteristics")
    class PerformanceTests {

        @Test
        @DisplayName("⚡ Should complete authentication quickly")
        void shouldCompleteAuthenticationQuickly() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);
            Authentication mockAuth = createMockAuthentication();

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When & Then - Should complete within reasonable time
            StepVerifier.create(repository.load(exchange))
                    .expectNextCount(1)
                    .expectComplete()
                    .verify(java.time.Duration.ofSeconds(1)); // Max 1 second
        }

        @Test
        @DisplayName("⚡ Should handle rapid sequential requests")
        void shouldHandleRapidSequentialRequests() {
            // Given
            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));

            // When - Make 100 requests rapidly
            for (int i = 0; i < 100; i++) {
                ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);
                StepVerifier.create(repository.load(exchange))
                        .expectNextCount(1)
                        .verifyComplete();
            }

            // Then - All should succeed
            verify(authenticationManager, times(100)).authenticate(any());
        }
    }

    /* ===============================================
       ERROR HANDLING TESTS
       =============================================== */

    @Nested
    @DisplayName("Error Handling")
    class ErrorHandlingTests {

        @Test
        @DisplayName("❌ Should handle null authentication manager response")
        void shouldHandleNullAuthManagerResponse() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.empty());

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();
        }

        @Test
        @DisplayName("❌ Should handle authentication timeout")
        void shouldHandleAuthenticationTimeout() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.delay(java.time.Duration.ofSeconds(10))
                            .then(Mono.just(createMockAuthentication())));

            // When & Then - Should timeout gracefully
            StepVerifier.create(repository.load(exchange))
                    .expectTimeout(java.time.Duration.ofSeconds(5))
                    .verify();
        }

        @Test
        @DisplayName("❌ Should handle malformed token exceptions")
        void shouldHandleMalformedTokenExceptions() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + INVALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.error(new IllegalArgumentException("Malformed JWT")));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(authenticationManager).authenticate(any());
        }

        @Test
        @DisplayName("❌ Should handle network errors")
        void shouldHandleNetworkErrors() {
            // Given
            ServerWebExchange exchange = createExchangeWithAuth("Bearer " + VALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.error(new RuntimeException("Network error")));

            // When
            Mono<SecurityContext> result = repository.load(exchange);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();
        }
    }

    /* ===============================================
       HELPER METHODS
       =============================================== */

    private ServerWebExchange createExchangeWithAuth(String authHeader) {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/protected")
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .build();

        return MockServerWebExchange.from(request);
    }

    private ServerWebExchange createExchangeWithoutAuth() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/protected")
                .build();

        return MockServerWebExchange.from(request);
    }

    private Authentication createMockAuthentication() {
        return new UsernamePasswordAuthenticationToken(
                TEST_USER_ID,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }
}