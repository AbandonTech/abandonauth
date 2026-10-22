-- Records a login that has been started with a provider. Expiry is measured
-- from the database clock so a wrong clock on an API host cannot extend it.
-- name: CreateAuthorizationState :exec
INSERT INTO oauth_authorization_state (
    state_hash,
    browser_binding_hash,
    provider,
    application_id,
    callback_uri,
    pkce_verifier_nonce,
    pkce_verifier_ciphertext,
    google_nonce_hash,
    auth_epoch,
    expires_at
)
SELECT
    $1, $2, $3, $4, $5, $6, $7, $8,
    auth_epoch.epoch,
    CURRENT_TIMESTAMP + make_interval(secs => sqlc.arg(lifetime_seconds)::double precision)
FROM auth_epoch
WHERE auth_epoch.singleton;

-- Consumes a login in progress. The row is only returned when it matches the
-- browser, provider, application and callback the login was started with, has
-- not expired, and was created under the current authority epoch.
-- name: ConsumeAuthorizationState :one
DELETE FROM oauth_authorization_state
USING auth_epoch
WHERE oauth_authorization_state.state_hash = $1
  AND oauth_authorization_state.browser_binding_hash = $2
  AND oauth_authorization_state.provider = $3
  AND oauth_authorization_state.expires_at > CURRENT_TIMESTAMP
  AND auth_epoch.singleton
  AND oauth_authorization_state.auth_epoch = auth_epoch.epoch
RETURNING
    oauth_authorization_state.application_id,
    oauth_authorization_state.callback_uri,
    oauth_authorization_state.pkce_verifier_nonce,
    oauth_authorization_state.pkce_verifier_ciphertext,
    oauth_authorization_state.google_nonce_hash;

-- name: DeleteExpiredAuthorizationState :execrows
DELETE FROM oauth_authorization_state
WHERE state_hash IN (
    SELECT state_hash
    FROM oauth_authorization_state
    WHERE expires_at <= CURRENT_TIMESTAMP
    LIMIT sqlc.arg(max_rows)
);

-- name: CreateExchangeCode :exec
INSERT INTO oauth_exchange_code (
    code_hash,
    user_id,
    application_id,
    provider,
    auth_epoch,
    expires_at
)
SELECT
    $1, $2, $3, $4,
    auth_epoch.epoch,
    CURRENT_TIMESTAMP + make_interval(secs => sqlc.arg(lifetime_seconds)::double precision)
FROM auth_epoch
WHERE auth_epoch.singleton;

-- Spends a one-time code. The application that presents it must be the one it
-- was issued to, so a code taken from another application's callback is refused
-- without revealing that it existed.
-- name: ConsumeExchangeCode :one
DELETE FROM oauth_exchange_code
USING auth_epoch
WHERE oauth_exchange_code.code_hash = $1
  AND oauth_exchange_code.application_id = $2
  AND oauth_exchange_code.expires_at > CURRENT_TIMESTAMP
  AND auth_epoch.singleton
  AND oauth_exchange_code.auth_epoch = auth_epoch.epoch
RETURNING
    oauth_exchange_code.user_id,
    oauth_exchange_code.application_id,
    oauth_exchange_code.provider;

-- Removes a code without spending it, for the endpoint that withdraws a
-- credential. It does not report whether the code existed.
-- name: DeleteExchangeCode :execrows
DELETE FROM oauth_exchange_code
WHERE code_hash = $1;

-- name: DeleteExpiredExchangeCodes :execrows
DELETE FROM oauth_exchange_code
WHERE code_hash IN (
    SELECT code_hash
    FROM oauth_exchange_code
    WHERE expires_at <= CURRENT_TIMESTAMP
    LIMIT sqlc.arg(max_rows)
);
