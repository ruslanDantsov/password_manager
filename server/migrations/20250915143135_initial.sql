-- Create "users" table
CREATE TABLE users (
                       id UUID PRIMARY KEY,
                       email TEXT NOT NULL UNIQUE,
                       password_hash TEXT NOT NULL,
                       display_name TEXT,
                       created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for faster lookup by email
CREATE UNIQUE INDEX users_email_idx ON users (email);