-- +goose Up
-- +goose StatementBegin
create table "User"
(
    username text                           not null,
    id       uuid default gen_random_uuid() not null
        primary key
);

create table "DiscordAccount"
(
    id      bigint not null
        primary key,
    user_id uuid   not null
        references "User"
            on update cascade on delete cascade
);

create unique index "DiscordAccount_user_id_key"
    on "DiscordAccount" (user_id);

create table "GitHubAccount"
(
    id      integer not null
        primary key,
    user_id uuid    not null
        references "User"
            on update cascade on delete cascade
);

create unique index "GitHubAccount_user_id_key"
    on "GitHubAccount" (user_id);

create table "GoogleAccount"
(
    id      text not null
        primary key,
    user_id uuid not null
        references "User"
            on update cascade on delete cascade
);

create unique index "GoogleAccount_user_id_key"
    on "GoogleAccount" (user_id);

create table "DeveloperApplication"
(
    id            uuid default gen_random_uuid()   not null
        primary key,
    owner_id      uuid                             not null
        references "User"
            on update cascade on delete cascade,
    refresh_token text                             not null,
    name          text default 'Application'::text not null
);

create sequence "CallbackUri_id_seq"
    as integer;
create table "CallbackUri"
(
    id                       serial
        primary key,
    developer_application_id uuid not null
        references "DeveloperApplication"
            on update cascade on delete cascade,
    uri                      text not null
);
alter sequence "CallbackUri_id_seq" owned by "CallbackUri".id;

create unique index "CallbackUri_developer_application_id_uri_key"
    on "CallbackUri" (developer_application_id, uri);

create sequence passwordaccount_id_seq;
create table "PasswordAccount"
(
    id       bigint default nextval('passwordaccount_id_seq'::regclass) not null
        primary key,
    password text                                                       not null,
    user_id  uuid                                                       not null
        references "User"
            on update cascade on delete cascade
);
alter sequence passwordaccount_id_seq owned by "PasswordAccount".id;

create unique index "PasswordAccount_user_id_key"
    on "PasswordAccount" (user_id);
-- +goose StatementEnd