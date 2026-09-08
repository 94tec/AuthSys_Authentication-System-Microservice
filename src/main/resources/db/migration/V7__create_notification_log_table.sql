-- ============================================================
-- V7__create_notification_log_table.sql
-- Damuchi Safaris — Notification module
-- ============================================================

CREATE TABLE IF NOT EXISTS notification_log (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Recipient (resolved at send time for audit)
    customer_id             VARCHAR(128)    NOT NULL,
    recipient_email         VARCHAR(255),
    recipient_phone         VARCHAR(20),
    recipient_name          VARCHAR(200),

    -- Classification
    notification_type       VARCHAR(30)     NOT NULL
                            CHECK (notification_type IN (
                                'BOOKING_CREATED','BOOKING_CONFIRMED','BOOKING_CANCELLED',
                                'BOOKING_COMPLETED','BOOKING_REMINDER',
                                'PAYMENT_RECEIVED','PAYMENT_FAILED','PAYMENT_REFUNDED',
                                'ACCOUNT_APPROVED','ACCOUNT_REJECTED',
                                'WELCOME','PASSWORD_RESET',
                                'PROMOTIONAL','REVIEW_REQUEST'
                            )),

    channel                 VARCHAR(15)     NOT NULL
                            CHECK (channel IN ('EMAIL','SMS','WHATSAPP','IN_APP')),

    status                  VARCHAR(15)     NOT NULL DEFAULT 'PENDING'
                            CHECK (status IN ('PENDING','SENT','DELIVERED','FAILED','SKIPPED')),

    -- Correlation
    correlation_id          UUID            NOT NULL,
    reference_id            VARCHAR(36),
    reference_type          VARCHAR(20),

    -- Content (stored for audit and retry)
    subject                 VARCHAR(200),
    body                    TEXT,

    -- Delivery tracking
    provider_message_id     VARCHAR(200),
    attempts                INTEGER         NOT NULL DEFAULT 0,
    last_attempt_at         TIMESTAMPTZ,
    delivered_at            TIMESTAMPTZ,
    error_message           VARCHAR(500),

    -- BaseEntity audit fields
    is_deleted              BOOLEAN         NOT NULL DEFAULT FALSE,
    version                 BIGINT,
    created_by              VARCHAR(100),
    created_date            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_modified_by        VARCHAR(100),
    last_modified_date      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────────────────────

-- Customer notification bell feed — most queried
CREATE INDEX IF NOT EXISTS idx_notif_customer
    ON notification_log(customer_id, created_date DESC)
    WHERE is_deleted = FALSE;

-- Type + status for monitoring dashboard
CREATE INDEX IF NOT EXISTS idx_notif_type
    ON notification_log(notification_type);

CREATE INDEX IF NOT EXISTS idx_notif_status
    ON notification_log(status);

CREATE INDEX IF NOT EXISTS idx_notif_channel
    ON notification_log(channel);

-- Groups all channels for one event (EMAIL + SMS + WhatsApp rows)
CREATE INDEX IF NOT EXISTS idx_notif_correlation
    ON notification_log(correlation_id);

-- Staff lookup: all notifications for a booking or payment
CREATE INDEX IF NOT EXISTS idx_notif_reference
    ON notification_log(reference_id);

-- Time-based monitoring
CREATE INDEX IF NOT EXISTS idx_notif_created
    ON notification_log(created_date DESC);

-- Retry queue — ScheduledNotificationJob polls this combination
CREATE INDEX IF NOT EXISTS idx_notif_pending_retry
    ON notification_log(status, attempts, created_date)
    WHERE status IN ('FAILED', 'PENDING');

-- Provider callback matching (Africa's Talking delivery reports)
CREATE INDEX IF NOT EXISTS idx_notif_provider_msg
    ON notification_log(provider_message_id)
    WHERE provider_message_id IS NOT NULL;

COMMENT ON TABLE notification_log IS
    'Audit record for every notification attempt — one row per channel per event. '
    'correlationId groups all channel rows for the same logical notification.';

COMMENT ON COLUMN notification_log.body IS
    'Rendered message body at time of send — stored for audit and retry replay.';

COMMENT ON COLUMN notification_log.correlation_id IS
    'Groups EMAIL + SMS + WhatsApp rows for the same event. '
    'e.g. BOOKING_CONFIRMED fires 3 rows — all share this UUID.';
