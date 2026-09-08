-- ============================================================
-- V6__create_customer_tables.sql
-- Damuchi Safaris — Customer Profile module
-- ============================================================

CREATE TABLE IF NOT EXISTS customer_profiles (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Firebase UID — unique, not updatable
    customer_id             VARCHAR(128)    NOT NULL UNIQUE,

    -- Core identity (synced from auth on login)
    first_name              VARCHAR(100)    NOT NULL,
    last_name               VARCHAR(100)    NOT NULL,
    email                   VARCHAR(255)    NOT NULL,
    phone_number            VARCHAR(20),

    -- Profile details
    bio                     VARCHAR(500),
    country                 VARCHAR(100),
    photo_url               VARCHAR(500),
    date_of_birth           DATE,
    nationality             VARCHAR(100),
    dietary_notes           VARCHAR(500),

    -- Communication preferences
    email_marketing_opt_in  BOOLEAN         NOT NULL DEFAULT FALSE,
    sms_opt_in              BOOLEAN         NOT NULL DEFAULT FALSE,

    -- Stats (denormalised — updated by scheduled job)
    total_tours_completed   INTEGER         NOT NULL DEFAULT 0,
    total_spent             NUMERIC(14, 2),

    -- BaseEntity audit fields
    is_deleted              BOOLEAN         NOT NULL DEFAULT FALSE,
    version                 BIGINT,
    created_by              VARCHAR(100),
    created_date            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_modified_by        VARCHAR(100),
    last_modified_date      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Saved travel documents (passport, national ID, etc.)
CREATE TABLE IF NOT EXISTS travel_documents (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    customer_profile_id     UUID            NOT NULL
                            REFERENCES customer_profiles(id) ON DELETE CASCADE,

    document_type           VARCHAR(20)     NOT NULL
                            CHECK (document_type IN (
                                'PASSPORT','NATIONAL_ID','ALIEN_CARD',
                                'BIRTH_CERTIFICATE','OTHER')),

    full_name               VARCHAR(150)    NOT NULL,
    document_number         VARCHAR(50)     NOT NULL,
    nationality             VARCHAR(100),
    issuing_country         VARCHAR(100),
    date_of_birth           DATE,
    expiry_date             DATE,
    label                   VARCHAR(100),
    primary_document        BOOLEAN         NOT NULL DEFAULT FALSE,

    -- BaseEntity audit fields
    is_deleted              BOOLEAN         NOT NULL DEFAULT FALSE,
    version                 BIGINT,
    created_by              VARCHAR(100),
    created_date            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_modified_by        VARCHAR(100),
    last_modified_date      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Wishlist — saved enquire-button.tsx IDs per customer
CREATE TABLE IF NOT EXISTS customer_wishlist (
    customer_profile_id     UUID            NOT NULL
                            REFERENCES customer_profiles(id) ON DELETE CASCADE,
    tour_id                 UUID            NOT NULL,
    PRIMARY KEY (customer_profile_id, tour_id)
);

-- ── Indexes ──────────────────────────────────────────────────────────────────

-- Primary customer lookup by Firebase UID
CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_uid
    ON customer_profiles(customer_id)
    WHERE is_deleted = FALSE;

-- Staff email/name search
CREATE INDEX IF NOT EXISTS idx_customer_email
    ON customer_profiles(email)
    WHERE is_deleted = FALSE;

-- FTS index for staff name search
CREATE INDEX IF NOT EXISTS idx_customer_name_fts
    ON customer_profiles
    USING gin(to_tsvector('english',
        first_name || ' ' || last_name || ' ' || email));

-- Document lookups
CREATE INDEX IF NOT EXISTS idx_doc_customer
    ON travel_documents(customer_profile_id)
    WHERE is_deleted = FALSE;

CREATE INDEX IF NOT EXISTS idx_doc_type
    ON travel_documents(document_type)
    WHERE is_deleted = FALSE;

-- Expiry date — for scheduled job that warns customers before trips
CREATE INDEX IF NOT EXISTS idx_doc_expiry
    ON travel_documents(expiry_date)
    WHERE is_deleted = FALSE AND expiry_date IS NOT NULL;

-- Only one primary document per customer — partial unique index
CREATE UNIQUE INDEX IF NOT EXISTS idx_doc_primary_per_customer
    ON travel_documents(customer_profile_id)
    WHERE primary_document = TRUE AND is_deleted = FALSE;

-- Wishlist enquire-button.tsx lookup
CREATE INDEX IF NOT EXISTS idx_wishlist_tour
    ON customer_wishlist(tour_id);

COMMENT ON TABLE customer_profiles IS
    'Damuchi Safaris — extended customer profile linked to Firebase auth by UID';

COMMENT ON TABLE travel_documents IS
    'Saved passport/ID templates — reused across bookings to pre-fill traveler forms';

COMMENT ON TABLE customer_wishlist IS
    'Customer saved enquire-button.tsx IDs — no FK to tours so wishlists survive enquire-button.tsx deletion';

COMMENT ON COLUMN customer_profiles.customer_id IS
    'Firebase UID — the join key between auth system and this module. '
    'No FK to a users table — Firebase is the source of truth for auth.';

COMMENT ON COLUMN travel_documents.primary_document IS
    'Only one document per customer can be primary. '
    'Enforced by partial unique index idx_doc_primary_per_customer.';
