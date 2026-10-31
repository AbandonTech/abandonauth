-- +goose Up
-- +goose StatementBegin
-- A Steam ID is an unsigned 64-bit integer, wider than BIGINT holds, so it is
-- kept as its decimal spelling.
CREATE TABLE "SteamAccount" (
    "id" TEXT NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "SteamAccount_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "SteamAccount_user_id_key" ON "SteamAccount"("user_id");

ALTER TABLE "SteamAccount" ADD CONSTRAINT "SteamAccount_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Which providers a login or code may name is decided by the application, so the
-- tables keep no list of them. A Steam sign-in has no PKCE verifier to hold.
ALTER TABLE oauth_authorization_state
    DROP CONSTRAINT oauth_authorization_state_provider_check,
    ALTER COLUMN pkce_verifier_nonce DROP NOT NULL,
    ALTER COLUMN pkce_verifier_ciphertext DROP NOT NULL;

ALTER TABLE oauth_exchange_code
    DROP CONSTRAINT oauth_exchange_code_provider_check;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Locked before any row changes, in the order rotate-auth-epoch takes them, so
-- the two cannot deadlock.
LOCK TABLE oauth_authorization_state, oauth_exchange_code IN ACCESS EXCLUSIVE MODE;

DELETE FROM oauth_authorization_state WHERE provider = 'steam';
DELETE FROM oauth_exchange_code WHERE provider = 'steam';

DROP TABLE "SteamAccount";

ALTER TABLE oauth_authorization_state
    ADD CONSTRAINT oauth_authorization_state_provider_check
        CHECK (provider IN ('discord', 'github', 'google')),
    ALTER COLUMN pkce_verifier_nonce SET NOT NULL,
    ALTER COLUMN pkce_verifier_ciphertext SET NOT NULL;

ALTER TABLE oauth_exchange_code
    ADD CONSTRAINT oauth_exchange_code_provider_check
        CHECK (provider IN ('discord', 'github', 'google'));
-- +goose StatementEnd
