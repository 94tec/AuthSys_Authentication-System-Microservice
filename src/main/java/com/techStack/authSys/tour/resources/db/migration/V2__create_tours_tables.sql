-- ============================================================
-- V2__create_tours_tables.sql
-- Damuchi Safaris — Tour module
-- ============================================================

CREATE TABLE IF NOT EXISTS tours (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(150)        NOT NULL,
    slug                VARCHAR(200)        NOT NULL UNIQUE,
    description         TEXT                NOT NULL,
    short_description   VARCHAR(1000),
    price_per_person    NUMERIC(10, 2)      NOT NULL,
    max_capacity        INTEGER             NOT NULL,
    duration_hours      INTEGER             NOT NULL,
    category            VARCHAR(50)         NOT NULL,
    difficulty          VARCHAR(20)         NOT NULL,
    departure_location  VARCHAR(300)        NOT NULL,
    destination         VARCHAR(300)        NOT NULL,
    min_age             INTEGER,
    max_group_size      INTEGER,
    active              BOOLEAN             NOT NULL DEFAULT TRUE,
    featured            BOOLEAN             NOT NULL DEFAULT FALSE,
    average_rating      NUMERIC(3, 2),
    total_reviews       INTEGER             NOT NULL DEFAULT 0,
    total_bookings      INTEGER             NOT NULL DEFAULT 0,
    is_deleted          BOOLEAN             NOT NULL DEFAULT FALSE,
    version             BIGINT,
    created_by          VARCHAR(100),
    created_date        TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    last_modified_by    VARCHAR(100),
    last_modified_date  TIMESTAMPTZ         NOT NULL DEFAULT NOW()
);

-- Image URLs (one-to-many via collection table)
CREATE TABLE IF NOT EXISTS tour_images (
    tour_id     UUID            NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    image_url   VARCHAR(500)    NOT NULL
);

-- Inclusions
CREATE TABLE IF NOT EXISTS tour_inclusions (
    tour_id     UUID            NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    inclusion   VARCHAR(200)    NOT NULL
);

-- Exclusions
CREATE TABLE IF NOT EXISTS tour_exclusions (
    tour_id     UUID            NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    exclusion   VARCHAR(200)    NOT NULL
);

-- Highlights
CREATE TABLE IF NOT EXISTS tour_highlights (
    tour_id     UUID            NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    highlight   VARCHAR(300)    NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_tour_slug        ON tours(slug);
CREATE INDEX IF NOT EXISTS idx_tour_category    ON tours(category);
CREATE INDEX IF NOT EXISTS idx_tour_active      ON tours(active);
CREATE INDEX IF NOT EXISTS idx_tour_featured    ON tours(featured, active);
CREATE INDEX IF NOT EXISTS idx_tour_deleted     ON tours(is_deleted);
CREATE INDEX IF NOT EXISTS idx_tour_destination ON tours(destination);

-- Full-text search index
CREATE INDEX IF NOT EXISTS idx_tour_fts ON tours
    USING gin(to_tsvector('english', name || ' ' || destination || ' ' || description));

COMMENT ON TABLE tours IS 'Damuchi Safaris — available tours and packages';
