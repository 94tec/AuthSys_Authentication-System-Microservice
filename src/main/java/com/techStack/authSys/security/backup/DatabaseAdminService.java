package com.techStack.authSys.security.backup;

import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Read-only database administration surface for SUPER_ADMIN.
 *
 * Deliberately does NOT expose raw SQL execution over HTTP — that's an
 * unbounded RCE-shaped attack surface even behind SUPER_ADMIN auth (one
 * leaked token or session-fixation bug away from a full data breach).
 * Everything here is a fixed, parameterless, read-only query. Anything
 * beyond this (schema changes, one-off data fixes) should go through
 * Flyway migrations reviewed in your normal deploy pipeline, or a direct
 * `psql` session over your VPN/bastion — not through the app's API surface.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DatabaseAdminService {

    private final DataSource dataSource;
    private final org.flywaydb.core.Flyway flyway;

    public Mono<Map<String, Object>> getConnectionPoolStats() {
        return Mono.fromCallable(() -> {
            Map<String, Object> stats = new LinkedHashMap<>();
            if (dataSource instanceof HikariDataSource hikari) {
                HikariPoolMXBean pool = hikari.getHikariPoolMXBean();
                stats.put("poolName", hikari.getPoolName());
                stats.put("activeConnections", pool.getActiveConnections());
                stats.put("idleConnections", pool.getIdleConnections());
                stats.put("totalConnections", pool.getTotalConnections());
                stats.put("threadsAwaitingConnection", pool.getThreadsAwaitingConnection());
                stats.put("maxPoolSize", hikari.getMaximumPoolSize());
            } else {
                stats.put("info", "Connection pool metrics unavailable — not a HikariDataSource");
            }
            return stats;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Map<String, Object>> getDatabaseInfo() {
        return Mono.fromCallable(() -> {
            Map<String, Object> info = new LinkedHashMap<>();
            try (Connection conn = dataSource.getConnection()) {
                DatabaseMetaData meta = conn.getMetaData();
                info.put("productName", meta.getDatabaseProductName());
                info.put("productVersion", meta.getDatabaseProductVersion());
                info.put("driverVersion", meta.getDriverVersion());
                info.put("url", maskCredentials(meta.getURL()));
                info.put("readOnly", conn.isReadOnly());
            }
            return info;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /** Row counts for the core tables — quick sanity check, not a substitute for real monitoring. */
    public Mono<Map<String, Long>> getTableRowCounts() {
        String[] tables = {
                "users", "security_incidents", "role_permission_overrides",
                "system_configs", "security_policies", "api_keys",
                "tours", "tour_availability", "bookings", "notification_log", "audit_entries"
        };
        return Mono.fromCallable(() -> {
            Map<String, Long> counts = new LinkedHashMap<>();
            try (Connection conn = dataSource.getConnection(); Statement stmt = conn.createStatement()) {
                for (String table : tables) {
                    try (ResultSet rs = stmt.executeQuery(
                            "SELECT COUNT(*) FROM " + table)) { // table names are fixed constants above, not user input
                        if (rs.next()) {
                            counts.put(table, rs.getLong(1));
                        }
                    } catch (Exception e) {
                        counts.put(table, -1L); // table doesn't exist yet in this environment — skip, don't fail whole request
                    }
                }
            }
            return counts;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /** Flyway migration status — requires flyway-core on the classpath (you already have it). */
    public Mono<Map<String, Object>> getMigrationStatus() {
        return Mono.fromCallable(() -> {
            var info = flyway.info();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("currentVersion", info.current() != null ? info.current().getVersion().toString() : "none");
            result.put("pendingCount", info.pending().length);
            result.put("appliedCount", info.applied().length);
            return result;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private String maskCredentials(String jdbcUrl) {
        if (jdbcUrl == null) return null;
        return jdbcUrl.replaceAll("password=[^&;]*", "password=****");
    }
}
