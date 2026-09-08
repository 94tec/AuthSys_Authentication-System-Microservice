package com.techStack.authSys.security.backup;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

@Tag(
        name = "Admin · Database",
        description = "Read-only database administration for SUPER_ADMIN. No query execution is exposed here " +
                "by design — schema changes and one-off fixes go through Flyway migrations or a direct psql " +
                "session, not this API surface."
)
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping(value = "/api/admin/database", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
@PreAuthorize("hasRole('SUPER_ADMIN')")
public class DatabaseAdminController {

    private final DatabaseAdminService databaseAdminService;

    @Operation(
            summary = "Get HikariCP connection pool stats",
            description = "Returns active/idle/total connection counts and pool configuration. " +
                    "Returns an informational message instead if the configured DataSource isn't Hikari-backed."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Pool stats retrieved"),
            @ApiResponse(responseCode = "403", description = "Caller is not SUPER_ADMIN")
    })
    @GetMapping("/pool")
    public Mono<ResponseEntity<Map<String, Object>>> getPoolStats() {
        return databaseAdminService.getConnectionPoolStats().map(ResponseEntity::ok);
    }

    @Operation(
            summary = "Get database connection metadata",
            description = "Product name/version, driver version, and connection URL (credentials masked)."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Database info retrieved"),
            @ApiResponse(responseCode = "403", description = "Caller is not SUPER_ADMIN")
    })
    @GetMapping("/info")
    public Mono<ResponseEntity<Map<String, Object>>> getInfo() {
        return databaseAdminService.getDatabaseInfo().map(ResponseEntity::ok);
    }

    @Operation(
            summary = "Get row counts for core tables",
            description = "Fixed, parameterless COUNT(*) per known table. Tables that don't exist yet in this " +
                    "environment are reported as -1 and filtered out client-side rather than failing the request."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Row counts retrieved"),
            @ApiResponse(responseCode = "403", description = "Caller is not SUPER_ADMIN")
    })
    @GetMapping("/table-counts")
    public Mono<ResponseEntity<Map<String, Long>>> getTableCounts() {
        return databaseAdminService.getTableRowCounts().map(ResponseEntity::ok);
    }

    @Operation(
            summary = "Get Flyway migration status",
            description = "Current applied version plus counts of applied and pending migrations."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Migration status retrieved"),
            @ApiResponse(responseCode = "403", description = "Caller is not SUPER_ADMIN")
    })
    @GetMapping("/migration-status")
    public Mono<ResponseEntity<Map<String, Object>>> getMigrationStatus() {
        return databaseAdminService.getMigrationStatus().map(ResponseEntity::ok);
    }
}