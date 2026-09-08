-- Adjust the version prefix (V__) to the next number in your own Flyway sequence
-- before running — this assumes it's a fresh addition, not a re-run.

CREATE TABLE tours (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity
    name                   VARCHAR(150)  NOT NULL,
    slug                   VARCHAR(180)  NOT NULL UNIQUE,
    short_description      VARCHAR(500)  NOT NULL,
    description            TEXT          NOT NULL,
    category               VARCHAR(50)   NOT NULL,

    -- Destination
    destination            VARCHAR(150)  NOT NULL,
    country                VARCHAR(100)  NOT NULL,
    region                 VARCHAR(150),
    meeting_point          VARCHAR(300),

    -- Trip details
    duration_days          INTEGER       NOT NULL,
    duration_nights        INTEGER       NOT NULL,
    difficulty             VARCHAR(30)   NOT NULL,
    minimum_age            INTEGER,
    max_group_size         INTEGER,
    best_season            VARCHAR(200),

    -- Pricing
    price                  NUMERIC(12,2) NOT NULL,
    currency               VARCHAR(3)    NOT NULL,
    price_type             VARCHAR(30)   NOT NULL,
    deposit_percentage     NUMERIC(5,2),

    -- Content (long-form single fields; list fields live in child tables below)
    important_information  TEXT,

    -- Media
    cover_image            VARCHAR(1000) NOT NULL,
    video_url              VARCHAR(1000),

    -- Ratings
    average_rating         NUMERIC(3,2)  NOT NULL DEFAULT 0,
    review_count           BIGINT        NOT NULL DEFAULT 0,

    -- Publishing (Tour-specific; `deleted` is now `is_deleted` via BaseEntity)
    active                 BOOLEAN       NOT NULL DEFAULT TRUE,
    featured               BOOLEAN       NOT NULL DEFAULT FALSE,

    -- Audit (must match com.techStack.authSys.common.models.BaseEntity exactly)
    created_by             VARCHAR(100),
    created_date           TIMESTAMPTZ   NOT NULL DEFAULT now(),
    last_modified_by       VARCHAR(100),
    last_modified_date     TIMESTAMPTZ   NOT NULL DEFAULT now(),
    is_deleted             BOOLEAN       NOT NULL DEFAULT FALSE,
    version                BIGINT
);

CREATE INDEX idx_tour_slug        ON tours (slug);
CREATE INDEX idx_tour_category    ON tours (category);
CREATE INDEX idx_tour_active      ON tours (active);
CREATE INDEX idx_tour_featured    ON tours (featured);
CREATE INDEX idx_tour_destination ON tours (destination);

-- ── Element collection tables ──────────────────────────────────────────
-- Mirrors @ElementCollection mappings on the Tour entity exactly:
-- table name, join column, and value column must match or Hibernate will
-- fail to map on startup.

CREATE TABLE tour_highlights (
    tour_id   UUID NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    highlight TEXT NOT NULL
);
CREATE INDEX idx_tour_highlights_tour_id ON tour_highlights (tour_id);

CREATE TABLE tour_itinerary (
    tour_id    UUID    NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    day_order  INTEGER NOT NULL,
    activity   TEXT    NOT NULL
);
CREATE INDEX idx_tour_itinerary_tour_id ON tour_itinerary (tour_id);

CREATE TABLE tour_inclusions (
    tour_id   UUID NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    inclusion TEXT NOT NULL
);
CREATE INDEX idx_tour_inclusions_tour_id ON tour_inclusions (tour_id);

CREATE TABLE tour_exclusions (
    tour_id   UUID NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    exclusion TEXT NOT NULL
);
CREATE INDEX idx_tour_exclusions_tour_id ON tour_exclusions (tour_id);

CREATE TABLE tour_requirements (
    tour_id     UUID NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    requirement TEXT NOT NULL
);
CREATE INDEX idx_tour_requirements_tour_id ON tour_requirements (tour_id);

CREATE TABLE tour_gallery (
    tour_id   UUID          NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    image_url VARCHAR(1000) NOT NULL
);
CREATE INDEX idx_tour_gallery_tour_id ON tour_gallery (tour_id);