-- name: CreateDeveloperApplication :one
INSERT INTO "DeveloperApplication" ("owner_id", "refresh_token", "name")
VALUES ($1, $2, $3)
RETURNING "id", "owner_id", "name", "refresh_token", "credential_version";

-- name: GetDeveloperApplication :one
SELECT "id", "owner_id", "name", "refresh_token", "credential_version"
FROM "DeveloperApplication"
WHERE "id" = $1;

-- Ordered by name so the list a developer sees is stable between requests.
-- name: ListDeveloperApplicationsByOwner :many
SELECT "id", "owner_id", "name", "refresh_token", "credential_version"
FROM "DeveloperApplication"
WHERE "owner_id" = $1
ORDER BY "name", "id";

-- name: DeleteDeveloperApplication :one
DELETE FROM "DeveloperApplication"
WHERE "id" = $1
RETURNING "id", "owner_id", "name", "refresh_token", "credential_version";

-- Replaces the stored credential and invalidates every access token already
-- issued to this application in the same statement, so no token can be minted
-- against the old credential and survive the reset.
-- name: ResetDeveloperApplicationCredential :one
UPDATE "DeveloperApplication"
SET "refresh_token" = $2,
    "credential_version" = "credential_version" + 1
WHERE "id" = $1
RETURNING "id", "owner_id", "name", "refresh_token", "credential_version";

-- name: ListCallbackUris :many
SELECT "id", "developer_application_id", "uri"
FROM "CallbackUri"
WHERE "developer_application_id" = $1
ORDER BY "uri", "id";

-- name: CreateCallbackUri :exec
INSERT INTO "CallbackUri" ("developer_application_id", "uri")
VALUES ($1, $2);

-- name: DeleteCallbackUri :exec
DELETE FROM "CallbackUri"
WHERE "id" = $1;

-- Exact match. A callback is only accepted if the application registered that
-- precise string, so no prefix or normalised form is compared.
-- name: CallbackUriIsRegistered :one
SELECT EXISTS (
    SELECT 1
    FROM "CallbackUri"
    WHERE "developer_application_id" = $1
      AND "uri" = $2
) AS registered;
