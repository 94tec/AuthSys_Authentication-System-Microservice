ALTER TABLE enquiry_quotes
    ADD COLUMN adult_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE enquiry_quotes
    ADD COLUMN child_count INTEGER NOT NULL DEFAULT 0;