-- Create "users" table
CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       email TEXT NOT NULL UNIQUE,
                       password_hash TEXT NOT NULL,
                       display_name TEXT,
                       salt BYTEA NOT NULL,
                       encrypted_data_key BYTEA NOT NULL,
                       created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for faster lookup by email
CREATE UNIQUE INDEX users_email_idx ON users (email);