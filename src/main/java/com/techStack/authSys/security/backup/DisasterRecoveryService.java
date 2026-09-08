package com.techStack.authSys.security.backup;

import com.techStack.authSys.security.audit.ActionType;
import com.techStack.authSys.security.audit.AuditLogService;
import com.techStack.authSys.security.models.BackupJob;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Manual, on-demand backup trigger for SUPER_ADMIN.
 *
 * IMPORTANT — this is a SUPPLEMENT, not a replacement, for your hosting
 * provider's automated backups (e.g. Render/managed Postgres point-in-time
 * recovery, or a scheduled `pg_dump` cron on your VPS). Application-triggered
 * backups are useful for "back this up right now before I run a risky
 * migration" moments, not as your primary disaster-recovery strategy —
 * a backup that lives on the same box as the database it backs up doesn't
 * protect you if that box is lost. Ship dumps to off-box storage (S3-
 * compatible bucket) as a follow-up hardening step; a TODO is left below.
 *
 * Requires the `pg_dump` binary to be present on the runtime host/image
 * matching your Postgres major version.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DisasterRecoveryService {

    private final BackupJobRepository backupJobRepository;
    private final AuditLogService auditLogService;
    private final Clock clock;

    @Value("${spring.datasource.url}")
    private String jdbcUrl;

    @Value("${spring.datasource.username}")
    private String dbUsername;

    @Value("${security.admin.backup-directory:/var/backups/authsys}")
    private String backupDirectory;

    public Mono<BackupJob> triggerBackup(String triggeredBy) {
        return Mono.fromCallable(() -> {
                    BackupJob job = BackupJob.builder()
                            .status(BackupJob.BackupStatus.QUEUED)
                            .triggeredBy(triggeredBy)
                            .startedAt(clock.instant())
                            .build();
                    return backupJobRepository.save(job);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(job -> runBackupAsync(job, triggeredBy));
    }

    private void runBackupAsync(BackupJob job, String triggeredBy) {
        Mono.fromRunnable(() -> executeBackup(job))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> log.error("Backup {} failed: {}", job.getId(), e.getMessage()))
                .subscribe();
    }

    private void executeBackup(BackupJob job) {
        job.setStatus(BackupJob.BackupStatus.RUNNING);
        backupJobRepository.save(job);

        try {
            Path dir = Path.of(backupDirectory);
            Files.createDirectories(dir);

            String fileName = "authsys_backup_" +
                    DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss").format(
                            java.time.LocalDateTime.now(clock)) + ".sql.gz";
            Path outputFile = dir.resolve(fileName);

            String dbName = extractDbName(jdbcUrl);
            String host = extractHost(jdbcUrl);

            // pg_dump piped through gzip; PGPASSWORD supplied via env, never on argv/log
            ProcessBuilder pb = new ProcessBuilder(
                    "/bin/sh", "-c",
                    String.format("pg_dump -h %s -U %s -d %s | gzip > %s",
                            host, dbUsername, dbName, outputFile));
            pb.environment().put("PGPASSWORD", System.getenv().getOrDefault("DB_PASSWORD", ""));
            pb.redirectErrorStream(true);

            Process process = pb.start();
            boolean finished = process.waitFor(30, java.util.concurrent.TimeUnit.MINUTES);

            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("Backup timed out after 30 minutes");
            }
            if (process.exitValue() != 0) {
                throw new IllegalStateException("pg_dump exited with code " + process.exitValue());
            }

            long size = Files.size(outputFile);
            job.setStatus(BackupJob.BackupStatus.COMPLETED);
            job.setFileName(fileName);
            job.setFilePath(outputFile.toString());
            job.setFileSizeBytes(size);
            job.setCompletedAt(clock.instant());

            // TODO(production hardening): upload `outputFile` to an off-box S3-compatible
            // bucket here, then optionally delete the local copy — a local-only backup
            // does not protect against loss of the host itself.

            auditLogService.logAuditEvent(
                    job.getTriggeredBy(), ActionType.DATABASE_BACKUP_COMPLETED,
                    "Database backup completed: " + fileName,
                    Map.of("fileSizeBytes", size, "jobId", job.getId())
            ).subscribe();

        } catch (Exception e) {
            job.setStatus(BackupJob.BackupStatus.FAILED);
            job.setErrorMessage(e.getMessage());
            job.setCompletedAt(clock.instant());
            log.error("❌ Database backup failed for job {}: {}", job.getId(), e.getMessage());
        } finally {
            backupJobRepository.save(job);
        }
    }

    public Mono<List<BackupJob>> listBackups() {
        return Mono.fromCallable(backupJobRepository::findAllByOrderByStartedAtDesc)
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<BackupJob> getBackupStatus(String jobId) {
        return Mono.fromCallable(() -> backupJobRepository.findById(jobId)
                        .orElseThrow(() -> new IllegalArgumentException("Backup job not found: " + jobId)))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private String extractDbName(String jdbcUrl) {
        // jdbc:postgresql://host:port/dbname?params
        String withoutParams = jdbcUrl.split("\\?")[0];
        return withoutParams.substring(withoutParams.lastIndexOf('/') + 1);
    }

    private String extractHost(String jdbcUrl) {
        String afterScheme = jdbcUrl.replaceFirst("^jdbc:postgresql://", "");
        String hostPort = afterScheme.split("/")[0];
        return hostPort.split(":")[0];
    }
}
