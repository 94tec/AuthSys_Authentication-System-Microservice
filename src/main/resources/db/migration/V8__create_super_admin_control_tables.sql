-- ============================================================================
-- Security incidents: append-only log of security-relevant events
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_incidents (
    id UUID PRIMARY KEY,

    created_by VARCHAR(100),
    created_date TIMESTAMP WITH TIME ZONE NOT NULL,
    last_modified_by VARCHAR(100),
    last_modified_date TIMESTAMP WITH TIME ZONE NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT,

    type VARCHAR(40) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description VARCHAR(500),
    user_id VARCHAR(36),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_by VARCHAR(36),
    resolved_at TIMESTAMP,
    resolution_notes VARCHAR(500),
    metadata_json TEXT
    );

CREATE INDEX IF NOT EXISTS idx_incident_type
    ON security_incidents(type);

CREATE INDEX IF NOT EXISTS idx_incident_severity
    ON security_incidents(severity);

CREATE INDEX IF NOT EXISTS idx_incident_created
    ON security_incidents(created_date);

CREATE INDEX IF NOT EXISTS idx_incident_resolved
    ON security_incidents(resolved);

CREATE INDEX IF NOT EXISTS idx_incident_ip
    ON security_incidents(ip_address);


-- ============================================================================
-- Backup jobs
-- ============================================================================

CREATE TABLE IF NOT EXISTS backup_jobs (
    id UUID PRIMARY KEY,

    created_by VARCHAR(100),
    created_date TIMESTAMP WITH TIME ZONE NOT NULL,
    last_modified_by VARCHAR(100),
    last_modified_date TIMESTAMP WITH TIME ZONE NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT,

    status VARCHAR(20) NOT NULL,
    file_name VARCHAR(255),
    file_path VARCHAR(500),
    file_size_bytes BIGINT,
    triggered_by VARCHAR(36),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message VARCHAR(1000)
    );

CREATE INDEX IF NOT EXISTS idx_backup_status
    ON backup_jobs(status);

CREATE INDEX IF NOT EXISTS idx_backup_started
    ON backup_jobs(started_at);


-- ============================================================================
-- Role Permission Overrides
-- (Does NOT extend BaseEntity, so it keeps created_at/updated_at)
-- ============================================================================

CREATE TABLE IF NOT EXISTS role_permission_overrides (

    id BIGSERIAL PRIMARY KEY,

    role VARCHAR(30) NOT NULL,
    permission VARCHAR(150) NOT NULL,
    granted BOOLEAN NOT NULL,

    set_by VARCHAR(128) NOT NULL,
    reason VARCHAR(500) NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT uq_role_permission
    UNIQUE (role, permission),

    CONSTRAINT chk_super_admin_override
    CHECK (role <> 'SUPER_ADMIN')
    );

CREATE INDEX IF NOT EXISTS idx_rpo_role
    ON role_permission_overrides(role);

CREATE INDEX IF NOT EXISTS idx_rpo_permission
    ON role_permission_overrides(permission);

CREATE INDEX IF NOT EXISTS idx_rpo_granted
    ON role_permission_overrides(granted);