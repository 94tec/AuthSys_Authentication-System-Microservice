-- ============================================================
-- V3__create_bookings_tables.sql
-- Damuchi Safaris — Booking module
-- ============================================================

CREATE TABLE IF NOT EXISTS bookings (
    id                   UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Customer (Firebase UID, no FK)
    customer_id          VARCHAR(128)    NOT NULL,
    customer_email       VARCHAR(255)    NOT NULL,
    customer_name        VARCHAR(200)    NOT NULL,

    -- Tour & slot references
    tour_id              UUID            NOT NULL REFERENCES tours(id),
    availability_id      UUID            NOT NULL REFERENCES tour_availability(id),

    -- Denormalised for manifest queries without joins
    tour_date            DATE            NOT NULL,
    tour_name            VARCHAR(200)    NOT NULL,

    -- Pricing snapshot (frozen at booking time)
    traveler_count       INTEGER         NOT NULL,
    price_per_traveler   NUMERIC(10, 2)  NOT NULL,
    total_price          NUMERIC(12, 2)  NOT NULL,
    currency             CHAR(3)         NOT NULL DEFAULT 'KES',

    -- Status & payment lifecycle
    status               VARCHAR(30)     NOT NULL DEFAULT 'PENDING_PAYMENT',
    payment_reference    VARCHAR(100),
    paid_at              TIMESTAMPTZ,
    cancelled_at         TIMESTAMPTZ,
    cancellation_reason  VARCHAR(500),
    refund_reference     VARCHAR(100),
    refunded_at          TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,

    -- Extra
    special_requests     VARCHAR(1000),

    -- BaseEntity audit fields
    is_deleted           BOOLEAN         NOT NULL DEFAULT FALSE,
    version              BIGINT,
    created_by           VARCHAR(100),
    created_date         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_modified_by     VARCHAR(100),
    last_modified_date   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_booking_status CHECK (status IN (
        'PENDING_PAYMENT', 'CONFIRMED', 'COMPLETED', 'CANCELLED', 'REFUNDED'
    )),
    CONSTRAINT chk_traveler_count CHECK (traveler_count >= 1),
    CONSTRAINT chk_total_price    CHECK (total_price >= 0)
);

-- Traveler list for each booking
CREATE TABLE IF NOT EXISTS booking_travelers (
    booking_id       UUID            NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
    full_name        VARCHAR(150)    NOT NULL,
    date_of_birth    DATE,
    passport_number  VARCHAR(50),
    nationality      VARCHAR(100),
    dietary_notes    VARCHAR(500),
    lead_traveler    BOOLEAN         NOT NULL DEFAULT FALSE
);

-- ── Indexes ────────────────────────────────────────────────────────────────────

-- Customer lookups (getMyBookings, getMyActiveBookings, IDOR guard)
CREATE INDEX IF NOT EXISTS idx_booking_customer
    ON bookings(customer_id)
    WHERE is_deleted = FALSE;

-- Staff: by tour
CREATE INDEX IF NOT EXISTS idx_booking_tour
    ON bookings(tour_id)
    WHERE is_deleted = FALSE;

-- Staff: by availability slot (getBookingsByDate join)
CREATE INDEX IF NOT EXISTS idx_booking_availability
    ON bookings(availability_id)
    WHERE is_deleted = FALSE;

-- Staff: filter by status
CREATE INDEX IF NOT EXISTS idx_booking_status
    ON bookings(status)
    WHERE is_deleted = FALSE;

-- Staff: daily manifest
CREATE INDEX IF NOT EXISTS idx_booking_tour_date
    ON bookings(tour_date)
    WHERE is_deleted = FALSE;

-- Soft-delete filter
CREATE INDEX IF NOT EXISTS idx_booking_deleted
    ON bookings(is_deleted);

-- Compound: duplicate booking guard (countActiveBookingForCustomerOnSlot)
CREATE INDEX IF NOT EXISTS idx_booking_customer_slot
    ON bookings(availability_id, customer_id, status)
    WHERE is_deleted = FALSE;

COMMENT ON TABLE bookings          IS 'Damuchi Safaris — customer tour bookings';
COMMENT ON TABLE booking_travelers IS 'Traveler details per booking (lead + additional)';
