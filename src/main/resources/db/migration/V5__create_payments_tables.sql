-- ============================================================
-- V5__create_payments_tables.sql
-- Damuchi Safaris — Payment module
-- ============================================================

CREATE TABLE IF NOT EXISTS payments (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Booking reference
    booking_id              UUID            NOT NULL REFERENCES bookings(id),

    -- Denormalised customer ID (Firebase UID)
    customer_id             VARCHAR(128)    NOT NULL,

    -- Amount
    amount                  NUMERIC(12, 2)  NOT NULL CHECK (amount > 0),
    currency                VARCHAR(3)         NOT NULL DEFAULT 'KES',

    -- Method & status
    method                  VARCHAR(20)     NOT NULL DEFAULT 'MPESA'
                            CHECK (method IN ('MPESA','CARD','BANK_TRANSFER','CASH')),
    status                  VARCHAR(20)     NOT NULL DEFAULT 'PENDING'
                            CHECK (status IN ('PENDING','SUCCESS','FAILED','CANCELLED','REFUNDED')),

    -- M-Pesa Daraja fields
    phone_number            VARCHAR(20),
    checkout_request_id     VARCHAR(100),   -- Safaricom's STK request ID (callback key)
    merchant_request_id     VARCHAR(100),   -- Safaricom's merchant request ID
    mpesa_receipt_number    VARCHAR(50),    -- Transaction receipt on SUCCESS
    result_code             INTEGER,        -- 0 = success, else failure code
    result_description      VARCHAR(300),   -- Human-readable result from Safaricom
    raw_callback_payload    TEXT,           -- Full JSON callback body (audit)

    -- Timestamps
    initiated_at            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    completed_at            TIMESTAMPTZ,

    -- BaseEntity audit fields
    is_deleted              BOOLEAN         NOT NULL DEFAULT FALSE,
    version                 BIGINT,
    created_by              VARCHAR(100),
    created_date            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_modified_by        VARCHAR(100),
    last_modified_date      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ── Indexes ──────────────────────────────────────────────────────────────────

-- Primary callback lookup — match Safaricom callback to payment row
CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_checkout_request
    ON payments(checkout_request_id)
    WHERE checkout_request_id IS NOT NULL;

-- Booking payments list and double-charge guard
CREATE INDEX IF NOT EXISTS idx_payment_booking
    ON payments(booking_id);

-- Customer payment history
CREATE INDEX IF NOT EXISTS idx_payment_customer
    ON payments(customer_id);

-- Status filtering (admin dashboard, stats)
CREATE INDEX IF NOT EXISTS idx_payment_status
    ON payments(status);

-- Receipt lookup for audit / customer service
CREATE INDEX IF NOT EXISTS idx_payment_mpesa_receipt
    ON payments(mpesa_receipt_number)
    WHERE mpesa_receipt_number IS NOT NULL;

-- Revenue queries (only SUCCESS payments need to be summed quickly)
CREATE INDEX IF NOT EXISTS idx_payment_success_amount
    ON payments(status, amount)
    WHERE status = 'SUCCESS';

COMMENT ON TABLE payments IS
    'Damuchi Safaris — one row per payment attempt. '
    'Multiple rows may exist per booking if earlier attempts failed.';

COMMENT ON COLUMN payments.checkout_request_id IS
    'Safaricom STK CheckoutRequestID — used to match async callback to this row.';

COMMENT ON COLUMN payments.raw_callback_payload IS
    'Full Safaricom callback JSON stored for audit and replay debugging.';

COMMENT ON COLUMN payments.version IS
    'JPA @Version — optimistic locking, inherited from BaseEntity.';
