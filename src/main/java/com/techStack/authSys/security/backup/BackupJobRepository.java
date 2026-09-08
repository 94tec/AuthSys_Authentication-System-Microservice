package com.techStack.authSys.security.backup;

import com.techStack.authSys.security.models.BackupJob;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BackupJobRepository extends JpaRepository<BackupJob, String> {
    List<BackupJob> findAllByOrderByStartedAtDesc();
}
