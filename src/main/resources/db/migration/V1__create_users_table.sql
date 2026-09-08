CREATE TABLE users (
    id UUID PRIMARY KEY,

    firebase_uid VARCHAR(128) UNIQUE,

    email VARCHAR(255) NOT NULL UNIQUE,

    username VARCHAR(50) UNIQUE,

    phone_number VARCHAR(20),

    first_name VARCHAR(50),

    last_name VARCHAR(50),

    profile_picture_url TEXT,

    status VARCHAR(30) NOT NULL DEFAULT 'PENDING_APPROVAL',

    approval_level VARCHAR(20),

    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    account_locked BOOLEAN NOT NULL DEFAULT FALSE,

    account_disabled BOOLEAN NOT NULL DEFAULT FALSE,

    email_verified BOOLEAN NOT NULL DEFAULT FALSE,

    last_login_at TIMESTAMP,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_firebase_uid
    ON users(firebase_uid);

CREATE INDEX idx_users_email
    ON users(email);

CREATE INDEX idx_users_username
    ON users(username);