-- name: GetUser :one
SELECT "id", "username"
FROM "User"
WHERE "id" = $1;

-- name: CreateUser :one
INSERT INTO "User" ("username")
VALUES ($1)
RETURNING "id", "username";
