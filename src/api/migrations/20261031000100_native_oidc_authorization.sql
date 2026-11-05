-- Installed public clients signing a person in with OpenID Connect
-- Authorization Code flow and PKCE.
--
-- Every value a browser or client carries is stored only as a domain-separated
-- digest, every lifetime is measured by the database clock, and every native
-- row is withdrawn by authority rotation except the public-client/user
-- relationships, which are lock anchors rather than credentials.

-- +goose Up
-- +goose StatementBegin

-- Locked before any row changes, in the order rotate-auth-epoch takes them, so
-- the two cannot deadlock.
LOCK TABLE oauth_authorization_state, oauth_exchange_code IN ACCESS EXCLUSIVE MODE;

-- A public client cannot protect a credential, so it holds none. The check
-- also stops a build that knows nothing of client types from resetting a
-- public row into a confidential client.
ALTER TABLE "DeveloperApplication"
    ADD COLUMN "client_type" TEXT NOT NULL DEFAULT 'confidential',
    ALTER COLUMN "refresh_token" DROP NOT NULL,
    ADD CONSTRAINT "DeveloperApplication_client_type_check"
        CHECK ("client_type" IN ('confidential', 'public')),
    ADD CONSTRAINT "DeveloperApplication_credential_matches_client_type"
        CHECK (
            ("client_type" = 'confidential' AND "refresh_token" IS NOT NULL)
            OR ("client_type" = 'public' AND "refresh_token" IS NULL)
        );

-- Locked by every creation and sweep of a native authorization, so counting
-- the authorizations in progress and inserting one cannot interleave.
CREATE TABLE oauth_native_authorization_capacity (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton)
);

INSERT INTO oauth_native_authorization_capacity (singleton) VALUES (TRUE);

-- One public client's authorization from its start to the redemption of its
-- code. The row is the capacity slot: it is deleted, never marked, when the
-- authorization ends.
CREATE TABLE oauth_native_authorization (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    application_id UUID NOT NULL
        REFERENCES "DeveloperApplication"("id") ON DELETE CASCADE,

    browser_binding_hash BYTEA NOT NULL
        CHECK (octet_length(browser_binding_hash) = 32),

    -- The exact redirect, port included, the response is appended to and the
    -- code is redeemed against.
    redirect_uri TEXT NOT NULL
        CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048),

    scopes TEXT NOT NULL
        CHECK (scopes IN (
            'openid', 'openid profile', 'openid offline_access', 'openid profile offline_access'
        )),

    client_state TEXT NOT NULL
        CHECK (client_state ~ '^[A-Za-z0-9_-]{43,128}$'),
    client_nonce TEXT NOT NULL
        CHECK (client_nonce ~ '^[A-Za-z0-9_-]{43,128}$'),
    code_challenge TEXT NOT NULL
        CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),

    stage TEXT NOT NULL
        CHECK (stage IN ('page', 'provider', 'consent', 'code')),

    page_handle_hash BYTEA UNIQUE
        CHECK (page_handle_hash IS NULL OR octet_length(page_handle_hash) = 32),

    consent_handle_hash BYTEA UNIQUE
        CHECK (consent_handle_hash IS NULL OR octet_length(consent_handle_hash) = 32),

    -- Who the provider authenticated and when, held only while the person
    -- decides. This is server-side state and grants the client nothing.
    consent_user_id UUID
        REFERENCES "User"("id") ON DELETE CASCADE,
    consent_authenticated_at TIMESTAMPTZ,

    auth_epoch UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_native_authorization_lifetime
        CHECK (expires_at = created_at + interval '5 minutes'),

    CONSTRAINT oauth_native_authorization_handle_matches_stage
        CHECK ((stage = 'page') = (page_handle_hash IS NOT NULL)),

    CONSTRAINT oauth_native_authorization_consent_matches_stage
        CHECK (
            (stage = 'consent') = (consent_handle_hash IS NOT NULL)
            AND (stage = 'consent') = (consent_user_id IS NOT NULL)
            AND (stage = 'consent') = (consent_authenticated_at IS NOT NULL)
        )
);

CREATE INDEX oauth_native_authorization_expires_at_idx
    ON oauth_native_authorization (expires_at);

-- A provider sign-in started from a public client's authorization page carries
-- the authorization it continues instead of a confidential callback.
ALTER TABLE oauth_authorization_state
    ADD COLUMN native_authorization_id UUID UNIQUE
        REFERENCES oauth_native_authorization(id) ON DELETE CASCADE,
    ALTER COLUMN callback_uri DROP NOT NULL,
    ADD CONSTRAINT oauth_authorization_state_one_continuation
        CHECK ((native_authorization_id IS NULL) = (callback_uri IS NOT NULL));

-- The code the person's approval ends in. The redirect, challenge, nonce and
-- scopes it is bound to are its authorization's, which it cannot outlive.
CREATE TABLE oauth_native_authorization_code (
    code_hash BYTEA PRIMARY KEY
        CHECK (octet_length(code_hash) = 32),

    authorization_id UUID NOT NULL UNIQUE
        REFERENCES oauth_native_authorization(id) ON DELETE CASCADE,

    user_id UUID NOT NULL
        REFERENCES "User"("id") ON DELETE CASCADE,

    authenticated_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_native_authorization_code_lifetime
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '120 seconds')
);

-- A person who has been issued tokens by one public client. The row is the
-- lock that serialises everything bounded per person and application, and the
-- anchor whose deletion ends their offline grants and revocations.
CREATE TABLE oauth_public_client_user (
    application_id UUID NOT NULL
        REFERENCES "DeveloperApplication"("id") ON DELETE CASCADE,
    user_id UUID NOT NULL
        REFERENCES "User"("id") ON DELETE CASCADE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT oauth_public_client_user_pkey PRIMARY KEY (application_id, user_id)
);

-- An offline grant. Its tokens rotate; a consumed token stays until the family
-- ends so presenting it again is recognised as reuse.
CREATE TABLE oauth_refresh_family (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    application_id UUID NOT NULL,
    user_id UUID NOT NULL,

    scopes TEXT NOT NULL
        CHECK (scopes IN ('openid offline_access', 'openid profile offline_access')),

    authenticated_at TIMESTAMPTZ NOT NULL,
    auth_epoch UUID NOT NULL,

    member_count INTEGER NOT NULL DEFAULT 1
        CHECK (member_count BETWEEN 1 AND 10000),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,

    -- When the current token expires. The family ends at the earlier of this
    -- and its absolute expiry.
    active_until TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_refresh_family_lifetime
        CHECK (expires_at = created_at + interval '90 days'),
    CONSTRAINT oauth_refresh_family_active_within_lifetime
        CHECK (active_until <= expires_at),

    CONSTRAINT oauth_refresh_family_client_user_fkey
        FOREIGN KEY (application_id, user_id)
        REFERENCES oauth_public_client_user (application_id, user_id) ON DELETE CASCADE
);

CREATE INDEX oauth_refresh_family_pair_idx
    ON oauth_refresh_family (application_id, user_id, created_at, id);

CREATE INDEX oauth_refresh_family_ends_at_idx
    ON oauth_refresh_family ((LEAST(expires_at, active_until)));

CREATE TABLE oauth_refresh_token (
    token_hash BYTEA PRIMARY KEY
        CHECK (octet_length(token_hash) = 32),

    family_id UUID NOT NULL
        REFERENCES oauth_refresh_family(id) ON DELETE CASCADE,

    consumed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_refresh_token_lifetime
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days')
);

CREATE UNIQUE INDEX oauth_refresh_token_one_current_idx
    ON oauth_refresh_token (family_id) WHERE consumed_at IS NULL;

-- OIDC access tokens revoked before they expire, so this service's own
-- UserInfo refuses them. Bounded per person and application by the service.
CREATE TABLE oauth_access_token_revocation (
    jti UUID PRIMARY KEY,

    application_id UUID NOT NULL,
    user_id UUID NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT oauth_access_token_revocation_client_user_fkey
        FOREIGN KEY (application_id, user_id)
        REFERENCES oauth_public_client_user (application_id, user_id) ON DELETE CASCADE
);

CREATE INDEX oauth_access_token_revocation_pair_idx
    ON oauth_access_token_revocation (application_id, user_id, expires_at);

CREATE INDEX oauth_access_token_revocation_expires_at_idx
    ON oauth_access_token_revocation (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Ends every native authorization, offline session and revocation and forgets
-- which people each public client has served. A public client is given a
-- credential no one holds, so it cannot authenticate until its owner resets it
-- under a build that knows client types.
LOCK TABLE oauth_authorization_state, oauth_exchange_code IN ACCESS EXCLUSIVE MODE;

DELETE FROM oauth_authorization_state WHERE native_authorization_id IS NOT NULL;

ALTER TABLE oauth_authorization_state
    DROP CONSTRAINT oauth_authorization_state_one_continuation,
    DROP COLUMN native_authorization_id,
    ALTER COLUMN callback_uri SET NOT NULL;

DROP TABLE oauth_access_token_revocation;
DROP TABLE oauth_refresh_token;
DROP TABLE oauth_refresh_family;
DROP TABLE oauth_public_client_user;
DROP TABLE oauth_native_authorization_code;
DROP TABLE oauth_native_authorization;
DROP TABLE oauth_native_authorization_capacity;

ALTER TABLE "DeveloperApplication"
    DROP CONSTRAINT "DeveloperApplication_credential_matches_client_type",
    DROP CONSTRAINT "DeveloperApplication_client_type_check";

-- The bcrypt hash, at cost 12, of a random value that was discarded when this
-- migration was written.
UPDATE "DeveloperApplication"
SET "refresh_token" = '$2a$12$Epl.aE1qIpIPTsDatQIlSe8YOp8mvzZhmGyXxQKKB5malsIxE7Zje'
WHERE "client_type" = 'public';

ALTER TABLE "DeveloperApplication"
    DROP COLUMN "client_type",
    ALTER COLUMN "refresh_token" SET NOT NULL;
-- +goose StatementEnd
