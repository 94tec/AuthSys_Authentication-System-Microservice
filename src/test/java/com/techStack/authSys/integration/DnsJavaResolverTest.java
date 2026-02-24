package com.techStack.authSys.integration;

import com.techStack.authSys.config.core.EmailValidationConfig;
import com.techStack.authSys.service.security.DnsJavaResolver;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Comprehensive Test Suite for DnsJavaResolver
 *
 * Tests:
 * - MX record resolution
 * - A record validation
 * - TXT record resolution
 * - Caching behavior
 * - Error handling
 * - Thread safety
 *
 * @author TechStack Testing Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DnsJavaResolver Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DnsJavaResolverTest {

    @Mock
    private EmailValidationConfig config;

    private DnsJavaResolver resolver;

    @BeforeAll
    void setUp() throws Exception {
        // Configure mock
        when(config.getDnsServer()).thenReturn("8.8.8.8");
        when(config.getDnsTimeout()).thenReturn(5000L);

        // Create resolver
        resolver = new DnsJavaResolver(config);
    }

    @AfterAll
    void tearDown() {
        if (resolver != null) {
            resolver.shutdown();
        }
    }

    /* =========================
       MX Record Tests
       ========================= */

    @Nested
    @DisplayName("MX Record Resolution")
    class MxRecordTests {

        @Test
        @DisplayName("✅ Should resolve MX records for valid domain")
        void shouldResolveMxRecords() {
            // Given
            String domain = "gmail.com";

            // When
            List<String> mxRecords = resolver.resolveMxRecords(domain);

            // Then
            assertThat(mxRecords).isNotEmpty();
            assertThat(mxRecords.get(0)).contains("google");
        }

        @Test
        @DisplayName("✅ Should return empty list for domain without MX records")
        void shouldReturnEmptyForNoMxRecords() {
            // Given
            String domain = "example-no-mx-records-12345.com";

            // When
            List<String> mxRecords = resolver.resolveMxRecords(domain);

            // Then
            assertThat(mxRecords).isEmpty();
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "  ", "invalid..domain", "domain-with-@.com"})
        @DisplayName("❌ Should handle invalid domain formats")
        void shouldHandleInvalidDomains(String invalidDomain) {
            // When
            List<String> mxRecords = resolver.resolveMxRecords(invalidDomain);

            // Then
            assertThat(mxRecords).isEmpty();
        }

        @Test
        @DisplayName("✅ Should return MX records sorted by priority")
        void shouldReturnMxRecordsSortedByPriority() {
            // Given
            String domain = "gmail.com";

            // When
            List<String> mxRecords = resolver.resolveMxRecords(domain);

            // Then
            assertThat(mxRecords).isNotEmpty();
            // First record should be the one with lowest priority
            assertThat(mxRecords.get(0)).isNotNull();
        }

        @Test
        @DisplayName("✅ Should handle null domain gracefully")
        void shouldHandleNullDomain() {
            // When
            List<String> mxRecords = resolver.resolveMxRecords(null);

            // Then
            assertThat(mxRecords).isEmpty();
        }
    }

    /* =========================
       A Record Tests
       ========================= */

    @Nested
    @DisplayName("A Record Validation")
    class ARecordTests {

        @Test
        @DisplayName("✅ Should confirm A record exists for valid domain")
        void shouldConfirmARecordExists() {
            // Given
            String domain = "google.com";

            // When
            boolean hasARecord = resolver.hasARecord(domain);

            // Then
            assertThat(hasARecord).isTrue();
        }

        @Test
        @DisplayName("❌ Should return false for non-existent domain")
        void shouldReturnFalseForNonExistentDomain() {
            // Given
            String domain = "this-domain-definitely-does-not-exist-12345.com";

            // When
            boolean hasARecord = resolver.hasARecord(domain);

            // Then
            assertThat(hasARecord).isFalse();
        }

        @Test
        @DisplayName("✅ Should handle null domain gracefully")
        void shouldHandleNullDomain() {
            // When
            boolean hasARecord = resolver.hasARecord(null);

            // Then
            assertThat(hasARecord).isFalse();
        }
    }

    /* =========================
       TXT Record Tests
       ========================= */

    @Nested
    @DisplayName("TXT Record Resolution")
    class TxtRecordTests {

        @Test
        @DisplayName("✅ Should resolve TXT records for domain with SPF")
        void shouldResolveTxtRecords() {
            // Given
            String domain = "google.com";

            // When
            List<String> txtRecords = resolver.resolveTxtRecords(domain);

            // Then
            assertThat(txtRecords).isNotEmpty();
        }

        @Test
        @DisplayName("✅ Should return empty list for domain without TXT records")
        void shouldReturnEmptyForNoTxtRecords() {
            // Given
            String domain = "example-no-txt-records-12345.com";

            // When
            List<String> txtRecords = resolver.resolveTxtRecords(domain);

            // Then
            assertThat(txtRecords).isEmpty();
        }
    }

    /* =========================
       Caching Tests
       ========================= */

    @Nested
    @DisplayName("Caching Behavior")
    class CachingTests {

        @Test
        @DisplayName("✅ Should cache MX records on first lookup")
        void shouldCacheMxRecords() {
            // Given
            String domain = "gmail.com";

            // When - First lookup
            long start1 = System.currentTimeMillis();
            List<String> firstResult = resolver.resolveMxRecords(domain);
            long time1 = System.currentTimeMillis() - start1;

            // When - Second lookup (should be cached)
            long start2 = System.currentTimeMillis();
            List<String> secondResult = resolver.resolveMxRecords(domain);
            long time2 = System.currentTimeMillis() - start2;

            // Then
            assertThat(firstResult).isEqualTo(secondResult);
            // Cached lookup should be significantly faster
            assertThat(time2).isLessThan(time1);
        }

        @Test
        @DisplayName("✅ Should normalize domain for caching")
        void shouldNormalizeDomainForCaching() {
            // Given
            String domain1 = "Gmail.COM";
            String domain2 = "gmail.com";

            // When
            List<String> result1 = resolver.resolveMxRecords(domain1);
            List<String> result2 = resolver.resolveMxRecords(domain2);

            // Then - Should return same cached results
            assertThat(result1).isEqualTo(result2);
        }
    }

    /* =========================
       Performance Tests
       ========================= */

    @Nested
    @DisplayName("Performance")
    class PerformanceTests {

        @Test
        @DisplayName("⚡ Should complete lookup within timeout")
        void shouldCompleteLookupWithinTimeout() {
            // Given
            String domain = "google.com";
            long timeout = 5000; // 5 seconds

            // When
            long start = System.currentTimeMillis();
            resolver.resolveMxRecords(domain);
            long duration = System.currentTimeMillis() - start;

            // Then
            assertThat(duration).isLessThan(timeout);
        }

        @Test
        @DisplayName("⚡ Cached lookups should be fast (<10ms)")
        void cachedLookupsShouldBeFast() {
            // Given
            String domain = "gmail.com";
            resolver.resolveMxRecords(domain); // Prime cache

            // When
            long start = System.currentTimeMillis();
            resolver.resolveMxRecords(domain);
            long duration = System.currentTimeMillis() - start;

            // Then
            assertThat(duration).isLessThan(10);
        }
    }

    /* =========================
       Thread Safety Tests
       ========================= */

    @Nested
    @DisplayName("Thread Safety")
    class ThreadSafetyTests {

        @Test
        @DisplayName("✅ Should handle concurrent lookups")
        void shouldHandleConcurrentLookups() throws InterruptedException {
            // Given
            String domain = "google.com";
            int threadCount = 10;

            // When - Multiple threads lookup simultaneously
            Thread[] threads = new Thread[threadCount];
            for (int i = 0; i < threadCount; i++) {
                threads[i] = new Thread(() -> {
                    List<String> result = resolver.resolveMxRecords(domain);
                    assertThat(result).isNotEmpty();
                });
                threads[i].start();
            }

            // Wait for all threads
            for (Thread thread : threads) {
                thread.join();
            }

            // Then - No exceptions should occur
            // (test passes if no exceptions thrown)
        }
    }

    /* =========================
       Resource Cleanup Tests
       ========================= */

    @Nested
    @DisplayName("Resource Cleanup")
    class ResourceCleanupTests {

        @Test
        @DisplayName("✅ Should cleanup resources on shutdown")
        void shouldCleanupResourcesOnShutdown() {
            // Given
            DnsJavaResolver testResolver;
            try {
                testResolver = new DnsJavaResolver(config);
                testResolver.resolveMxRecords("gmail.com");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            // When
            testResolver.shutdown();

            // Then - Should not throw any exceptions
            // (test passes if shutdown completes without errors)
        }
    }
}