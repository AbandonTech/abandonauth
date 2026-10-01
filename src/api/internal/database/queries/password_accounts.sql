-- name: GetPasswordAccountByUser :one
SELECT "id", "password", "user_id"
FROM "PasswordAccount"
WHERE "user_id" = $1;

-- name: CreatePasswordAccount :exec
INSERT INTO "PasswordAccount" ("password", "user_id")
VALUES ($1, $2);
