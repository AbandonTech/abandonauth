-- Accounts, developer applications and their callback URIs.
--
-- This migration reproduces the schema that already exists in the deployed
-- database, down to identifier quoting, constraint names, column order and the
-- name of the sequence behind "PasswordAccount"."id". A database that already
-- holds this schema is marked as having applied this migration by
-- `abandonauth database adopt-existing-schema` and the statements below are not
-- executed against it, so the two paths must agree exactly or a later migration
-- would behave differently on a new database than on the deployed one.
--
-- Table and column identifiers are quoted because they are mixed case. Renaming
-- them would rewrite live data for no functional gain and is deliberately not
-- part of this migration.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE "User" (
    -- "username" precedes "id" because the identifier column was replaced with
    -- a UUID after the table was created, which moved it to the end.
    "username" TEXT NOT NULL,
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DiscordAccount" (
    "id" BIGINT NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "DiscordAccount_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "GitHubAccount" (
    "id" INTEGER NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "GitHubAccount_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "GoogleAccount" (
    "id" TEXT NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "GoogleAccount_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DeveloperApplication" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "owner_id" UUID NOT NULL,
    "refresh_token" TEXT NOT NULL,
    "name" TEXT NOT NULL DEFAULT 'Application',

    CONSTRAINT "DeveloperApplication_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "CallbackUri" (
    "id" SERIAL NOT NULL,
    "developer_application_id" UUID NOT NULL,
    "uri" TEXT NOT NULL,

    CONSTRAINT "CallbackUri_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "PasswordAccount" (
    "id" BIGINT NOT NULL,
    "password" TEXT NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "PasswordAccount_pkey" PRIMARY KEY ("id")
);

-- The sequence is unquoted, and therefore lower case, in the deployed database.
CREATE SEQUENCE passwordaccount_id_seq;
ALTER TABLE "PasswordAccount" ALTER COLUMN "id" SET DEFAULT nextval('passwordaccount_id_seq');
ALTER SEQUENCE passwordaccount_id_seq OWNED BY "PasswordAccount"."id";

-- One account per provider identity, and one provider identity per user.
CREATE UNIQUE INDEX "DiscordAccount_user_id_key" ON "DiscordAccount"("user_id");
CREATE UNIQUE INDEX "GitHubAccount_user_id_key" ON "GitHubAccount"("user_id");
CREATE UNIQUE INDEX "GoogleAccount_user_id_key" ON "GoogleAccount"("user_id");
CREATE UNIQUE INDEX "PasswordAccount_user_id_key" ON "PasswordAccount"("user_id");

-- An application may register a callback URI once, so replacing the set of URIs
-- cannot create duplicates that would make exact matching ambiguous.
CREATE UNIQUE INDEX "CallbackUri_developer_application_id_uri_key"
    ON "CallbackUri"("developer_application_id", "uri");

-- Deleting a user removes every credential and application that identified them.
ALTER TABLE "DiscordAccount" ADD CONSTRAINT "DiscordAccount_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "GitHubAccount" ADD CONSTRAINT "GitHubAccount_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "GoogleAccount" ADD CONSTRAINT "GoogleAccount_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PasswordAccount" ADD CONSTRAINT "PasswordAccount_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "DeveloperApplication" ADD CONSTRAINT "DeveloperApplication_owner_id_fkey"
    FOREIGN KEY ("owner_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "CallbackUri" ADD CONSTRAINT "CallbackUri_developer_application_id_fkey"
    FOREIGN KEY ("developer_application_id") REFERENCES "DeveloperApplication"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Reversing this migration destroys every account. It exists for disposable test
-- databases; production recovery restores a backup instead.
DROP TABLE IF EXISTS "CallbackUri";
DROP TABLE IF EXISTS "DeveloperApplication";
DROP TABLE IF EXISTS "PasswordAccount";
DROP SEQUENCE IF EXISTS passwordaccount_id_seq;
DROP TABLE IF EXISTS "GoogleAccount";
DROP TABLE IF EXISTS "GitHubAccount";
DROP TABLE IF EXISTS "DiscordAccount";
DROP TABLE IF EXISTS "User";
-- +goose StatementEnd
