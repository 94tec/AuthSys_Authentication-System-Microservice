package com.techStack.authSys.security.incident;

import com.techStack.authSys.security.models.IncidentSeverity;
import com.techStack.authSys.security.models.IncidentType;
import com.techStack.authSys.security.models.SecurityIncident;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SecurityIncidentRepository extends JpaRepository<SecurityIncident, UUID> {

    Page<SecurityIncident> findByResolvedFalseOrderByCreatedDateDesc(Pageable pageable);

    Page<SecurityIncident> findBySeverityAndResolvedFalseOrderByCreatedDateDesc(
            IncidentSeverity severity, Pageable pageable);

    Page<SecurityIncident> findByTypeOrderByCreatedDateDesc(
            IncidentType type, Pageable pageable);

    Optional<SecurityIncident> findFirstByTypeAndIpAddressAndResolvedFalseAndCreatedDateAfter(
            IncidentType type, String ipAddress, Instant since);

    Optional<SecurityIncident> findFirstByTypeAndUserIdAndResolvedFalseAndCreatedDateAfter(
            IncidentType type, String userId, Instant since);

    @Query("""
        SELECT i
        FROM SecurityIncident i
        WHERE i.createdDate >= :since
        ORDER BY i.createdDate DESC
    """)
    List<SecurityIncident> findRecentSince(@Param("since") Instant since);

    List<SecurityIncident> findByIpAddressOrderByCreatedDateDesc(String ipAddress);

    long countBySeverityAndResolvedFalse(IncidentSeverity severity);

    long countByResolvedFalse();
}
