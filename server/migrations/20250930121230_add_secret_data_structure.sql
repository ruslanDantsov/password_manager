-- Create "secret_data" table
CREATE TABLE secret_data (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    type varchar(32) NOT NULL,
    service_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create "credentials" table
CREATE TABLE credentials (
    id BIGSERIAL PRIMARY KEY,
    secret_data_id BIGINT NOT NULL REFERENCES secret_data(id),
    login TEXT NOT NULL,
    password_encrypted BYTEA NOT NULL
);

-- Create "credentials" table
CREATE TABLE text_data (
    id BIGSERIAL PRIMARY KEY,
    secret_data_id BIGINT NOT NULL REFERENCES secret_data(id),
    content_encrypted BYTEA NOT NULL
);

-- Create "binary_data" table
CREATE TABLE bank_cards (
    id BIGSERIAL PRIMARY KEY,
    secret_data_id BIGINT NOT NULL REFERENCES secret_data(id),
    cardholder_name TEXT NOT NULL,
    card_number_encrypted BYTEA NOT NULL,
    expiry_month INTEGER  NOT NULL CHECK (expiry_month BETWEEN 1 AND 12),
    expiry_year INTEGER  NOT NULL,
    cvv_encrypted BYTEA NOT NULL
);