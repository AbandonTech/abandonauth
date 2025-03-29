-- name: GetUserIDByDiscordID :one
SELECT "User".id
FROM "User"
JOIN "DiscordAccount" ON "DiscordAccount".user_id = "User".id
WHERE "DiscordAccount".id = sqlc.arg(discordID);

-- name: GetUserIDByGitHubID :one
SELECT "User".id
FROM "User"
JOIN "GitHubAccount" ON "GitHubAccount".user_id = "User".id
WHERE "GitHubAccount".id = sqlc.arg(gitHubID);

-- name: CreateUserWithGitHubID :one
WITH "NewUser" AS (
    INSERT INTO "User" (username)
    VALUES ($1)
    RETURNING "User".id
)
INSERT INTO "GitHubAccount" (id, user_id)
SELECT 
    $2 AS id,
    "NewUser".id AS user_id
FROM "NewUser"
RETURNING "GitHubAccount".user_id;