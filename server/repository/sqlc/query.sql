-- name: CreatePayment :exec
INSERT INTO users (
    id,
    email,
    password_hash,
    display_name
) VALUES (
    @id,
    @email,
    @password_hash,
    @display_name
);

