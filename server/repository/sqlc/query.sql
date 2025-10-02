-- name: CreateUser :one
INSERT INTO users (
    email,
    password_hash,
    display_name,
    salt,
    encrypted_data_key,
    created_at
) VALUES (
    @email,
    @password_hash,
    @display_name,
    @salt,
    @encrypted_data_key,
    NOW()
) RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: CreateSecretData :one
INSERT INTO secret_data (user_id, type, service_name, created_at)
VALUES ($1, $2, $3, $4)
    RETURNING id, user_id, type, service_name, created_at;

-- name: CreateCredential :one
INSERT INTO credentials (secret_data_id, login, password_encrypted)
VALUES ($1, $2, $3)
    RETURNING id, secret_data_id, login, password_encrypted;

-- name: GetUserCredentials :many
SELECT
    sd.id,
    sd.type,
    sd.service_name,
    sd.created_at,
    c.login,
    c.password_encrypted
FROM secret_data sd
         INNER JOIN credentials c ON c.secret_data_id = sd.id
WHERE sd.user_id = $1 AND sd.type = 'credentials'
ORDER BY sd.created_at DESC;


-- name: CreateTextData :one
INSERT INTO text_data (secret_data_id, content_encrypted)
VALUES ($1, $2)
    RETURNING id, secret_data_id, content_encrypted;

-- name: GetUserTextData :many
SELECT
    sd.id,
    sd.type,
    sd.service_name,
    sd.created_at,
    t.content_encrypted
FROM secret_data sd
         INNER JOIN text_data t ON t.secret_data_id = sd.id
WHERE sd.user_id = $1 AND sd.type = 'note'
ORDER BY sd.created_at DESC;

-- name: CreateBankCard :one
INSERT INTO bank_cards (secret_data_id, cardholder_name, card_number_encrypted, expiry_month, expiry_year, cvv_encrypted)
VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING id, secret_data_id, cardholder_name, card_number_encrypted, expiry_month, expiry_year, cvv_encrypted;

-- name: GetUserBankCards :many
SELECT
    sd.id,
    sd.type,
    sd.service_name,
    sd.created_at,
    c.cardholder_name,
    c.card_number_encrypted,
    c.expiry_month,
    c.expiry_year,
    c.cvv_encrypted
FROM secret_data sd
         INNER JOIN bank_cards c ON c.secret_data_id = sd.id
WHERE sd.user_id = $1 AND sd.type = 'card'
ORDER BY sd.created_at DESC;