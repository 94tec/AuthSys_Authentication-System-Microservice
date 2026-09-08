-- ============================================================
-- V3__create_availability_tables.sql
-- Damuchi Safaris — Availability module
-- ============================================================

CREATE TABLE IF NOT EXISTS tour_availability (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ========================================================
    -- Tour reference
    -- ========================================================

    tour_id             UUID            NOT NULL
        REFERENCES tours(id),

    -- ========================================================
    -- Departure / return dates
    -- ========================================================

    date                DATE            NOT NULL,

    return_date         DATE            NOT NULL,

    -- ========================================================
    -- Capacity
    -- ========================================================

    max_slots           INTEGER         NOT NULL
        CHECK (max_slots >= 1),

    available_slots     INTEGER         NOT NULL
        CHECK (available_slots >= 0),

    -- ========================================================
    -- Status
    -- ========================================================

    status              VARCHAR(20)     NOT NULL DEFAULT 'OPEN'
        CHECK (
            status IN (
                'OPEN',
                'LIMITED',
                'FULL',
                'CLOSED',
                'CANCELLED'
            )
        ),

    -- ========================================================
    -- Optional booking cutoff
    -- ========================================================

    booking_deadline    TIMESTAMPTZ,

    -- ========================================================
    -- Optional per-date pricing override
    -- ========================================================

    price_override      NUMERIC(10, 2),

    currency            VARCHAR(3),

    -- ========================================================
    -- Internal staff notes
    -- ========================================================

    internal_notes      VARCHAR(500),

    -- ========================================================
    -- BaseEntity audit fields
    -- ========================================================

    is_deleted          BOOLEAN         NOT NULL DEFAULT FALSE,

    version             BIGINT,

    created_by          VARCHAR(100),

    created_date        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    last_modified_by    VARCHAR(100),

    last_modified_date  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    -- ========================================================
    -- Constraints
    -- ========================================================

    CONSTRAINT uq_availability_tour_date
        UNIQUE (tour_id, date),

    CONSTRAINT chk_available_lte_max
        CHECK (available_slots <= max_slots),

    CONSTRAINT chk_return_date
        CHECK (return_date >= date),

    CONSTRAINT chk_price_override
        CHECK (price_override IS NULL OR price_override >= 0)
);


-- ============================================================
-- Indexes
-- ============================================================

-- Availability by date
CREATE INDEX IF NOT EXISTS idx_availability_date
    ON tour_availability(date)
    WHERE is_deleted = FALSE;


-- Availability by enquire-button.tsx
CREATE INDEX IF NOT EXISTS idx_availability_tour
    ON tour_availability(tour_id)
    WHERE is_deleted = FALSE;


-- Availability by status
CREATE INDEX IF NOT EXISTS idx_availability_status
    ON tour_availability(status)
    WHERE is_deleted = FALSE;


-- Tour + date lookup
CREATE INDEX IF NOT EXISTS idx_availability_tour_date
    ON tour_availability(tour_id, date)
    WHERE is_deleted = FALSE;


-- Upcoming open/limited slots
CREATE INDEX IF NOT EXISTS idx_availability_upcoming_open
    ON tour_availability(tour_id, status, date)
    WHERE is_deleted = FALSE
        AND status IN ('OPEN', 'LIMITED');


-- ============================================================
-- Comments
-- ============================================================

COMMENT ON TABLE tour_availability IS
    'Damuchi Safaris — bookable departure dates per enquire-button.tsx';


COMMENT ON COLUMN tour_availability.date IS
    'Departure date for this enquire-button.tsx availability slot';


COMMENT ON COLUMN tour_availability.return_date IS
    'Expected return date for this specific departure';


COMMENT ON COLUMN tour_availability.max_slots IS
    'Total seats available when this departure was opened';


COMMENT ON COLUMN tour_availability.available_slots IS
    'Remaining bookable seats. Decremented by reserveSlots(), incremented by releaseSlots().';


COMMENT ON COLUMN tour_availability.status IS
    'Availability state: OPEN, LIMITED, FULL, CLOSED, or CANCELLED';


COMMENT ON COLUMN tour_availability.booking_deadline IS
    'Optional deadline after which new bookings are not accepted';


COMMENT ON COLUMN tour_availability.price_override IS
    'Optional per-date price override. NULL means use the enquire-button.tsx price.';


COMMENT ON COLUMN tour_availability.currency IS
    'Currency for price_override. NULL means use the enquire-button.tsx currency.';


COMMENT ON COLUMN tour_availability.version IS
    'JPA @Version field — optimistic locking for concurrent booking protection.';