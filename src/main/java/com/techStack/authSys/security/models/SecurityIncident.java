package com.techStack.authSys.security.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(
        name = "security_incidents",
        indexes = {
                @Index(name = "idx_incident_type", columnList = "type"),
                @Index(name = "idx_incident_severity", columnList = "severity"),
                @Index(name = "idx_incident_created", columnList = "created_date"),
                @Index(name = "idx_incident_resolved", columnList = "resolved"),
                @Index(name = "idx_incident_ip", columnList = "ip_address")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(callSuper = true)
public class SecurityIncident extends BaseEntity {

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, length = 40)
    private IncidentType type;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 20)
    private IncidentSeverity severity;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "user_id", length = 36)
    private String userId;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "occurrence_count", nullable = false)
    @Builder.Default
    private Integer occurrenceCount = 1;

    @Column(name = "resolved", nullable = false)
    @Builder.Default
    private Boolean resolved = false;

    @Column(name = "resolved_by", length = 36)
    private String resolvedBy;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @Column(name = "resolution_notes", length = 500)
    private String resolutionNotes;

    @Column(name = "metadata_json", columnDefinition = "TEXT")
    private String metadataJson;

}