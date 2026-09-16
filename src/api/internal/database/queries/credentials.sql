-- name: GetAuthEpoch :one
SELECT epoch, updated_at
FROM auth_epoch
WHERE singleton;

-- Replaces the epoch every credential is stamped with. Callers run this inside
-- the transaction that also clears logins in progress, one-time codes and
-- sessions, so nothing issued under the previous epoch survives.
-- name: RotateAuthEpoch :one
UPDATE auth_epoch
SET epoch = $1,
    updated_at = CURRENT_TIMESTAMP
WHERE singleton
RETURNING epoch, updated_at;

-- name: DeleteAllAuthorizationState :execrows
DELETE FROM oauth_authorization_state;

-- name: DeleteAllExchangeCodes :execrows
DELETE FROM oauth_exchange_code;

-- name: DeleteAllBrowserSessions :execrows
DELETE FROM browser_session;

-- name: DeleteAllRevocations :execrows
DELETE FROM jwt_revocation;

-- Withdrawing a token twice is not an error: the endpoint that does it reports
-- success either way so it cannot be used to discover whether a token exists.
-- name: RevokeToken :exec
INSERT INTO jwt_revocation (jti, auth_epoch, expires_at)
SELECT
    $1,
    auth_epoch.epoch,
    sqlc.arg(expires_at)
FROM auth_epoch
WHERE auth_epoch.singleton
ON CONFLICT (jti) DO NOTHING;

-- name: TokenIsRevoked :one
SELECT EXISTS (
    SELECT 1
    FROM jwt_revocation
    WHERE jti = $1
      AND expires_at > CURRENT_TIMESTAMP
) AS revoked;

-- name: DeleteExpiredRevocations :execrows
DELETE FROM jwt_revocation
WHERE jti IN (
    SELECT jti
    FROM jwt_revocation
    WHERE expires_at <= CURRENT_TIMESTAMP
    LIMIT sqlc.arg(max_rows)
);
