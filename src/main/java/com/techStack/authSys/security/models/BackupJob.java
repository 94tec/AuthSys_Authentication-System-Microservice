package com.techStack.authSys.security.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "backup_jobs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(callSuper = true)
public class BackupJob extends BaseEntity {

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private BackupStatus status;

    @Column(name = "file_name", length = 255)
    private String fileName;

    @Column(name = "file_path", length = 500)
    private String filePath;

    @Column(name = "file_size_bytes")
    private Long fileSizeBytes;

    @Column(name = "triggered_by", length = 36)
    private String triggeredBy;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "error_message", length = 1000)
    private String errorMessage;

    public enum BackupStatus {
        QUEUED,
        RUNNING,
        COMPLETED,
        FAILED
    }
}