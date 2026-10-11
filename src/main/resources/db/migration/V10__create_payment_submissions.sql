-- V10__create_payment_submissions.sql

CREATE TABLE payment_submissions (
                                     id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

                                     quote_id                    UUID NOT NULL,

                                     channel                     VARCHAR(20) NOT NULL,
                                     reference_code              VARCHAR(100) NOT NULL,
                                     amount_paid                 NUMERIC(12, 2) NOT NULL,
                                     payer_name                  VARCHAR(150),

                                     status                      VARCHAR(20) NOT NULL DEFAULT 'PENDING_VERIFICATION',

                                     verified_by                 VARCHAR(100),
                                     verified_at                 TIMESTAMPTZ,
                                     rejection_reason            VARCHAR(500),

                                     related_booking_id          UUID,
                                     related_booking_reference   VARCHAR(20),

                                     created_by                  VARCHAR(100),
                                     created_date                TIMESTAMPTZ NOT NULL DEFAULT now(),
                                     last_modified_by            VARCHAR(100),
                                     last_modified_date          TIMESTAMPTZ NOT NULL DEFAULT now(),
                                     is_deleted                  BOOLEAN NOT NULL DEFAULT FALSE,
                                     version                     BIGINT,

                                     CONSTRAINT fk_payment_submission_quote
                                         FOREIGN KEY (quote_id) REFERENCES enquiry_quotes (id),

                                     CONSTRAINT fk_payment_submission_booking
                                         FOREIGN KEY (related_booking_id) REFERENCES bookings (id),

                                     CONSTRAINT chk_payment_submission_channel
                                         CHECK (channel IN ('MPESA', 'BANK_TRANSFER')),

                                     CONSTRAINT chk_payment_submission_status
                                         CHECK (status IN ('PENDING_VERIFICATION', 'VERIFIED', 'REJECTED')),

                                     CONSTRAINT chk_payment_submission_amount_positive
                                         CHECK (amount_paid > 0)
);

CREATE INDEX idx_payment_submission_quote   ON payment_submissions (quote_id);
CREATE INDEX idx_payment_submission_status  ON payment_submissions (status);
CREATE INDEX idx_payment_submission_booking ON payment_submissions (related_booking_id) WHERE related_booking_id IS NOT NULL;

CREATE UNIQUE INDEX uq_payment_submission_pending_per_quote
    ON payment_submissions (quote_id)
    WHERE status = 'PENDING_VERIFICATION';