-- name: CreateBrowserSession :exec
INSERT INTO browser_session (
    session_hash,
    user_id,
    csrf_hash,
    auth_epoch,
    expires_at
)
SELECT
    $1, $2, $3,
    auth_epoch.epoch,
    CURRENT_TIMESTAMP + make_interval(secs => sqlc.arg(lifetime_seconds)::double precision)
FROM auth_epoch
WHERE auth_epoch.singleton;

-- Returns the signed-in user for a session cookie. Expiry is absolute: reading
-- the session does not extend it, so a stolen cookie cannot be kept alive by
-- using it.
-- name: GetBrowserSession :one
SELECT
    browser_session.user_id,
    browser_session.csrf_hash,
    browser_session.expires_at
FROM browser_session
JOIN auth_epoch ON auth_epoch.singleton AND auth_epoch.epoch = browser_session.auth_epoch
WHERE browser_session.session_hash = $1
  AND browser_session.expires_at > CURRENT_TIMESTAMP;

-- name: DeleteBrowserSession :execrows
DELETE FROM browser_session
WHERE session_hash = $1;

-- name: DeleteBrowserSessionsForUser :execrows
DELETE FROM browser_session
WHERE user_id = $1;

-- name: DeleteExpiredBrowserSessions :execrows
DELETE FROM browser_session
WHERE session_hash IN (
    SELECT session_hash
    FROM browser_session
    WHERE expires_at <= CURRENT_TIMESTAMP
    LIMIT sqlc.arg(max_rows)
);
