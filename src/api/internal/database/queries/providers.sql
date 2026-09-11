-- Looks the user up by the identifier the provider issued, never by name or
-- address, so two accounts that happen to share a display name are not merged.
-- name: GetUserByDiscordAccount :one
SELECT "User"."id", "User"."username"
FROM "User"
JOIN "DiscordAccount" ON "DiscordAccount"."user_id" = "User"."id"
WHERE "DiscordAccount"."id" = $1;

-- name: GetUserByGitHubAccount :one
SELECT "User"."id", "User"."username"
FROM "User"
JOIN "GitHubAccount" ON "GitHubAccount"."user_id" = "User"."id"
WHERE "GitHubAccount"."id" = $1;

-- name: GetUserByGoogleAccount :one
SELECT "User"."id", "User"."username"
FROM "User"
JOIN "GoogleAccount" ON "GoogleAccount"."user_id" = "User"."id"
WHERE "GoogleAccount"."id" = $1;

-- name: CreateDiscordAccount :exec
INSERT INTO "DiscordAccount" ("id", "user_id")
VALUES ($1, $2);

-- name: CreateGitHubAccount :exec
INSERT INTO "GitHubAccount" ("id", "user_id")
VALUES ($1, $2);

-- name: CreateGoogleAccount :exec
INSERT INTO "GoogleAccount" ("id", "user_id")
VALUES ($1, $2);
