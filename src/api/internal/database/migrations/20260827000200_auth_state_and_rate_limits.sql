-- Server-side authority for logins in progress, browser sessions, revoked
-- tokens and request limits.
--
-- Everything here is stored so that the database, not a signed value handed to a
-- client, decides whether a credential is still usable. One-time values are kept
-- only as hashes, sizes and value ranges are constrained in SQL so a malformed
-- row cannot be written by any code path, and expiry is compared against the
-- database clock so that a wrong clock on an API host cannot extend a
-- credential.

-- +goose Up
-- +goose StatementBegin

-- Incremented when an application's refresh token is reset. Access tokens carry
-- the version they were issued under, so every token minted before a reset stops
-- validating the moment the reset commits, including one issued concurrently by
-- a request that lost the race.
ALTER TABLE "DeveloperApplication"
    ADD COLUMN "credential_version" BIGINT NOT NULL DEFAULT 1;

ALTER TABLE "DeveloperApplication"
    ADD CONSTRAINT "DeveloperApplication_credential_version_positive"
    CHECK ("credential_version" > 0);

-- A single row whose value is stamped into every credential this service issues.
-- Rotating it invalidates all of them at once, which is what makes recovery from
-- a suspected key compromise a single transaction rather than a sweep.
CREATE TABLE auth_epoch (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    epoch UUID NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO auth_epoch (singleton, epoch) VALUES (TRUE, gen_random_uuid());

-- A login that has been started with a provider but not yet completed.
--
-- The row, not the state parameter, holds everything the callback must agree
-- with. The state value itself is never stored; only its hash is, so a database
-- reader cannot resume someone else's login.
CREATE TABLE oauth_authorization_state (
    state_hash BYTEA PRIMARY KEY
        CHECK (octet_length(state_hash) = 32),

    -- Ties the login to the browser that started it through a short-lived
    -- cookie, so a state value observed in a redirect is useless elsewhere.
    browser_binding_hash BYTEA NOT NULL
        CHECK (octet_length(browser_binding_hash) = 32),

    provider TEXT NOT NULL
        CHECK (provider IN ('discord', 'github', 'google')),

    application_id UUID NOT NULL
        REFERENCES "DeveloperApplication"("id") ON DELETE CASCADE,

    -- The exact callback the application registered, compared byte for byte
    -- when the provider returns.
    callback_uri TEXT NOT NULL,

    -- The PKCE verifier, encrypted with AES-GCM under a key derived from the
    -- signing secret. Storing it in clear would let a database reader complete a
    -- login they observed the authorization code for.
    pkce_verifier_nonce BYTEA NOT NULL
        CHECK (octet_length(pkce_verifier_nonce) = 12),
    pkce_verifier_ciphertext BYTEA NOT NULL
        CHECK (octet_length(pkce_verifier_ciphertext) > 16),

    -- Only an OpenID Connect login has a nonce to bind the identity token to.
    google_nonce_hash BYTEA
        CHECK (google_nonce_hash IS NULL OR octet_length(google_nonce_hash) = 32),

    auth_epoch UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_authorization_state_expiry_order
        CHECK (expires_at > created_at),

    CONSTRAINT oauth_authorization_state_nonce_matches_provider
        CHECK (
            (provider = 'google' AND google_nonce_hash IS NOT NULL)
            OR (provider <> 'google' AND google_nonce_hash IS NULL)
        )
);

CREATE INDEX oauth_authorization_state_expires_at_idx
    ON oauth_authorization_state (expires_at);

-- A one-time code handed to an application so it can collect an access token for
-- the user who just signed in. It is bound to the application it was issued for,
-- so a code intercepted from one application cannot be spent by another.
CREATE TABLE oauth_exchange_code (
    code_hash BYTEA PRIMARY KEY
        CHECK (octet_length(code_hash) = 32),

    user_id UUID NOT NULL
        REFERENCES "User"("id") ON DELETE CASCADE,

    application_id UUID NOT NULL
        REFERENCES "DeveloperApplication"("id") ON DELETE CASCADE,

    provider TEXT NOT NULL
        CHECK (provider IN ('discord', 'github', 'google')),

    auth_epoch UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_exchange_code_expiry_order
        CHECK (expires_at > created_at)
);

CREATE INDEX oauth_exchange_code_expires_at_idx
    ON oauth_exchange_code (expires_at);

-- A signed-in browser. The cookie carries a random value; only its hash is
-- stored, and deleting the row ends the session immediately for every worker.
CREATE TABLE browser_session (
    session_hash BYTEA PRIMARY KEY
        CHECK (octet_length(session_hash) = 32),

    user_id UUID NOT NULL
        REFERENCES "User"("id") ON DELETE CASCADE,

    -- Hash of the token the site echoes back in a request header, which proves
    -- the request was made by the site rather than by another origin that can
    -- merely cause the cookie to be sent.
    csrf_hash BYTEA NOT NULL
        CHECK (octet_length(csrf_hash) = 32),

    auth_epoch UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT browser_session_expiry_order
        CHECK (expires_at > created_at)
);

CREATE INDEX browser_session_expires_at_idx
    ON browser_session (expires_at);

-- Tokens withdrawn before they expire.
--
-- There is deliberately no foreign key to the user or application: deleting a
-- principal must not remove the record that its still-valid tokens are refused.
CREATE TABLE jwt_revocation (
    jti UUID PRIMARY KEY,
    auth_epoch UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX jwt_revocation_expires_at_idx
    ON jwt_revocation (expires_at);

-- Fixed request windows, counted in the database so that the limit holds across
-- every worker rather than per process.
--
-- bucket_key is a keyed hash of whatever identifies the caller. No client
-- address and no supplied secret is stored in clear.
CREATE TABLE rate_limit_bucket (
    bucket_key BYTEA NOT NULL
        CHECK (octet_length(bucket_key) = 32),

    endpoint_group TEXT NOT NULL
        CHECK (endpoint_group IN (
            'provider_callback',
            'login_exchange',
            'developer_application_login',
            'debug_password_auth',
            'developer_application_mutation',
            'burn_token'
        )),

    window_start TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,

    count BIGINT NOT NULL CHECK (count > 0),

    CONSTRAINT rate_limit_bucket_pkey
        PRIMARY KEY (bucket_key, endpoint_group, window_start),

    CONSTRAINT rate_limit_bucket_expiry_order
        CHECK (expires_at > window_start)
);

CREATE INDEX rate_limit_bucket_expires_at_idx
    ON rate_limit_bucket (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Reversing this migration signs every browser out and abandons every login in
-- progress. It exists for disposable test databases.
DROP TABLE IF EXISTS rate_limit_bucket;
DROP TABLE IF EXISTS jwt_revocation;
DROP TABLE IF EXISTS browser_session;
DROP TABLE IF EXISTS oauth_exchange_code;
DROP TABLE IF EXISTS oauth_authorization_state;
DROP TABLE IF EXISTS auth_epoch;

ALTER TABLE "DeveloperApplication"
    DROP CONSTRAINT IF EXISTS "DeveloperApplication_credential_version_positive";
ALTER TABLE "DeveloperApplication" DROP COLUMN IF EXISTS "credential_version";
-- +goose StatementEnd
