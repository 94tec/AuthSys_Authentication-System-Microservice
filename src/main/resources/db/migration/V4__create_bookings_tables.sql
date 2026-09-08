-- ============================================================
-- V4__create_bookings_tables.sql
-- Damuchi Safaris — Booking module
-- ============================================================

CREATE TABLE IF NOT EXISTS bookings (
    id   UUID PRIMARY KEY,

    -- ========================================================
    -- Booking reference
    -- ========================================================

    booking_reference    VARCHAR(20)     NOT NULL UNIQUE,

    -- ========================================================
    -- Customer
    -- Firebase UID — no FK because User lives in Firestore
    -- ========================================================

    customer_id          VARCHAR(128)    NOT NULL,
    customer_email       VARCHAR(255)    NOT NULL,
    customer_name        VARCHAR(255)    NOT NULL,

    -- ========================================================
    -- Tour & availability references
    -- ========================================================

    tour_id              UUID            NOT NULL
        REFERENCES tours(id),

    availability_id      UUID            NOT NULL
        REFERENCES tour_availability(id),

    -- Denormalised values for reporting/manifest queries
    tour_date            DATE            NOT NULL,
    tour_name            VARCHAR(150)    NOT NULL,

    -- ========================================================
    -- Party / Travelers
    -- ========================================================

    traveler_count       INTEGER         NOT NULL,
    number_of_adults     INTEGER         NOT NULL DEFAULT 0,
    number_of_children   INTEGER         NOT NULL DEFAULT 0,

    CONSTRAINT chk_booking_traveler_count
        CHECK (traveler_count >= 1),

    CONSTRAINT chk_booking_adults
        CHECK (number_of_adults >= 0),

    CONSTRAINT chk_booking_children
        CHECK (number_of_children >= 0),

    -- ========================================================
    -- Pricing snapshot
    -- ========================================================

    price_per_traveler   NUMERIC(10, 2)  NOT NULL,
    subtotal             NUMERIC(10, 2)  NOT NULL DEFAULT 0,
    discount             NUMERIC(10, 2)  NOT NULL DEFAULT 0,
    total_price          NUMERIC(10, 2)  NOT NULL,

    currency             VARCHAR(3)      NOT NULL DEFAULT 'KES',

    CONSTRAINT chk_booking_price_per_traveler
        CHECK (price_per_traveler >= 0),

    CONSTRAINT chk_booking_subtotal
        CHECK (subtotal >= 0),

    CONSTRAINT chk_booking_discount
        CHECK (discount >= 0),

    CONSTRAINT chk_booking_total_price
        CHECK (total_price >= 0),

    -- ========================================================
    -- Payment tracking
    -- ========================================================

    deposit_amount       NUMERIC(10, 2)  NOT NULL DEFAULT 0,
    amount_paid          NUMERIC(10, 2)  NOT NULL DEFAULT 0,
    balance_amount       NUMERIC(10, 2)  NOT NULL DEFAULT 0,

    payment_status       VARCHAR(20)     NOT NULL DEFAULT 'UNPAID',

    CONSTRAINT chk_booking_deposit_amount
        CHECK (deposit_amount >= 0),

    CONSTRAINT chk_booking_amount_paid
        CHECK (amount_paid >= 0),

    CONSTRAINT chk_booking_balance_amount
        CHECK (balance_amount >= 0),

    CONSTRAINT chk_booking_payment_status
        CHECK (payment_status IN (
            'UNPAID',
            'PARTIALLY_PAID',
            'PAID',
            'REFUNDED'
        )),

    -- ========================================================
    -- Booking lifecycle
    -- ========================================================

    status               VARCHAR(30)     NOT NULL DEFAULT 'PENDING_PAYMENT',

    CONSTRAINT chk_booking_status
        CHECK (status IN (
            'PENDING_PAYMENT',
            'CONFIRMED',
            'COMPLETED',
            'CANCELLED',
            'NO_SHOW'
        )),

    -- ========================================================
    -- Payment
    -- ========================================================

    payment_reference    VARCHAR(255),
    paid_at              TIMESTAMPTZ,

    -- ========================================================
    -- Cancellation / Refund
    -- ========================================================

    cancelled_at         TIMESTAMPTZ,
    cancellation_reason  VARCHAR(500),

    refund_reference     VARCHAR(255),
    refunded_at          TIMESTAMPTZ,

    -- ========================================================
    -- Customer notes
    -- ========================================================

    special_requests     VARCHAR(1000),

    -- ========================================================
    -- BaseEntity audit fields
    -- ========================================================

    is_deleted           BOOLEAN         NOT NULL DEFAULT FALSE,
    version              BIGINT,
    created_by           VARCHAR(100),
    created_date         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_modified_by     VARCHAR(100),
    last_modified_date   TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);


-- ============================================================
-- Booking travelers
-- ============================================================

CREATE TABLE IF NOT EXISTS booking_travelers (
    id                   UUID PRIMARY KEY,

    -- BaseEntity audit fields
    created_by           VARCHAR(100),
    created_date         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_modified_by     VARCHAR(100),
    last_modified_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted           BOOLEAN NOT NULL DEFAULT FALSE,
    version              BIGINT,

    -- Booking relationship
    booking_id           UUID NOT NULL
        REFERENCES bookings(id)
        ON DELETE CASCADE,

    -- Traveler information
    full_name            VARCHAR(255) NOT NULL,
    date_of_birth        DATE,
    passport_number      VARCHAR(50),
    nationality          VARCHAR(100),
    dietary_notes        VARCHAR(500),

    is_lead_traveler     BOOLEAN NOT NULL DEFAULT FALSE
);


-- ============================================================
-- Booking traveler indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_booking_travelers_booking_id
    ON booking_travelers(booking_id);


-- ============================================================
-- Booking indexes
-- ============================================================

-- Customer lookups
CREATE INDEX IF NOT EXISTS idx_booking_customer
    ON bookings(customer_id)
    WHERE is_deleted = FALSE;


-- Staff: by enquire-button.tsx
CREATE INDEX IF NOT EXISTS idx_booking_tour
    ON bookings(tour_id)
    WHERE is_deleted = FALSE;


-- Staff: by availability slot
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


-- Duplicate booking guard
CREATE INDEX IF NOT EXISTS idx_booking_customer_slot
    ON bookings(availability_id, customer_id, status)
    WHERE is_deleted = FALSE;


-- ============================================================
-- Comments
-- ============================================================

COMMENT ON TABLE bookings
    IS 'Damuchi Safaris — customer enquire-button.tsx bookings';

COMMENT ON TABLE booking_travelers
    IS 'Traveler details per booking (lead + additional)';
