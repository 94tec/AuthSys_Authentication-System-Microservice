-- V9__tour_enquiry_tables.sql
--
-- Tour enquiry lifecycle tables, combined into their final shape.
-- (Supersedes what was previously split across a base migration + a
--  V10 lifecycle-tracking ALTER migration -- merged here since neither
--  had shipped to a live environment yet. If either has already run
--  anywhere, don't retroactively merge; write a new forward migration
--  instead.)
--
-- Users live in Firestore (no FK on user_id / assigned_to).
-- Audit columns match com.techStack.authSys.common.models.BaseEntity.

-- ═══════════════════════════════════════════════════════════
-- 1. tour_enquiries
-- ═══════════════════════════════════════════════════════════

CREATE TABLE tour_enquiries (
                                id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Relations
                                tour_id               UUID NOT NULL REFERENCES tours(id),
                                user_id               VARCHAR(128) NOT NULL,     -- submitter, derived from JWT
                                assigned_to           VARCHAR(128),              -- staff member handling it

    -- Contact
                                full_name             VARCHAR(120) NOT NULL,
                                email                 VARCHAR(255) NOT NULL,
                                phone                 VARCHAR(32),
                                preferred_contact     VARCHAR(20),       -- PreferredContact enum: EMAIL / PHONE / WHATSAPP

    -- Trip request
                                preferred_date        DATE,
                                flexible_dates        BOOLEAN NOT NULL DEFAULT FALSE,
                                group_size_adults     INTEGER,
                                group_size_children   INTEGER,
                                budget_range          VARCHAR(100),
                                requirements          VARCHAR(2000),
                                source                VARCHAR(150),      -- where the lead came from (utm, referral, etc.)
                                consent               BOOLEAN NOT NULL DEFAULT TRUE,
                                notes                 TEXT,              -- internal notes, not shown to customer

    -- Status
                                status                VARCHAR(20) NOT NULL DEFAULT 'NEW',

    -- Lifecycle tracking
                                booking_reference     VARCHAR(60),
                                travel_start_date     DATE,
                                travel_end_date       DATE,
                                appreciation_sent_at  TIMESTAMPTZ,
                                first_contacted_at    TIMESTAMPTZ,

    -- BaseEntity: audit / soft-delete / optimistic lock
                                created_by            VARCHAR(100),
                                created_date          TIMESTAMPTZ NOT NULL DEFAULT now(),
                                last_modified_by      VARCHAR(100),
                                last_modified_date    TIMESTAMPTZ NOT NULL DEFAULT now(),
                                is_deleted            BOOLEAN NOT NULL DEFAULT FALSE,
                                version                BIGINT
);

CREATE INDEX idx_enquiry_tour            ON tour_enquiries (tour_id);
CREATE INDEX idx_enquiry_user            ON tour_enquiries (user_id);
CREATE INDEX idx_enquiry_status          ON tour_enquiries (status);
CREATE INDEX idx_enquiry_assigned_to     ON tour_enquiries (assigned_to);
CREATE INDEX idx_enquiry_created_at      ON tour_enquiries (created_date);
CREATE INDEX idx_enquiry_status_assigned ON tour_enquiries (status, assigned_to);
CREATE INDEX idx_enquiry_travel_end      ON tour_enquiries (travel_end_date);

-- ═══════════════════════════════════════════════════════════
-- 2. enquiry_events (audit trail of status changes, notes,
--    assignments -- actor/status columns included from the
--    start, so no later ALTER + backfill is needed)
-- ═══════════════════════════════════════════════════════════

CREATE TABLE enquiry_events (
                                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                enquiry_id  UUID NOT NULL REFERENCES tour_enquiries(id) ON DELETE CASCADE,

                                actor_id    VARCHAR(128),
                                actor_type  VARCHAR(20) NOT NULL,   -- ADMIN / CUSTOMER / SYSTEM
                                event_type  VARCHAR(50) NOT NULL,
                                from_status VARCHAR(20),
                                to_status   VARCHAR(20),
                                details     TEXT,

                                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_enquiry_events_enquiry_id ON enquiry_events (enquiry_id);

-- ═══════════════════════════════════════════════════════════
-- 3. enquiry_quotes -- same audit-column convention as
--    tour_enquiries (matches BaseEntity).
-- ═══════════════════════════════════════════════════════════

CREATE TABLE enquiry_quotes (
                                id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                enquiry_id          UUID NOT NULL REFERENCES tour_enquiries(id),

                                price_per_adult     NUMERIC(12,2) NOT NULL,
                                price_per_child     NUMERIC(12,2),
                                total_price         NUMERIC(12,2) NOT NULL,
                                currency            VARCHAR(3) NOT NULL,
                                valid_until         DATE NOT NULL,
                                inclusions_note     VARCHAR(2000),
                                internal_note       VARCHAR(1000),
                                status              VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
                                sent_at             TIMESTAMPTZ,
                                responded_at        TIMESTAMPTZ,

                                created_by          VARCHAR(100),
                                created_date        TIMESTAMPTZ NOT NULL DEFAULT now(),
                                last_modified_by    VARCHAR(100),
                                last_modified_date  TIMESTAMPTZ NOT NULL DEFAULT now(),
                                is_deleted          BOOLEAN NOT NULL DEFAULT FALSE,
                                version             BIGINT
);

CREATE INDEX idx_quote_enquiry       ON enquiry_quotes (enquiry_id);
CREATE INDEX idx_quote_status_valid  ON enquiry_quotes (status, valid_until);