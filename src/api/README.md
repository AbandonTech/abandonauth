# AbandonAuth API

The identity provider and OAuth application broker. One Go program: it serves
the API and runs the operational commands. It carries no migrations and never
changes the schema.

Settings, provider registration, deployment and the check commands are in the
[repository README](../../README.md).

## Commands

```text
abandonauth --version                      print the version this binary was built as
abandonauth serve                          answer API requests
abandonauth database rotate-auth-epoch     withdraw every issued credential
abandonauth provision                      create the site's application, asking for its UUID and the site origin
abandonauth provision --application-id <UUID> --site-url <ORIGIN>
                                           the same, asking for nothing; both flags or neither
```

`provision` reads `DATABASE_URL` from the environment only, needs a migrated
database, and changes nothing when an application already holds the
identifier. The [repository README](../../README.md#the-sites-application)
describes what it creates.

## Generated code

This is not committed, and is never edited by hand:

| Output | Generated from |
| --- | --- |
| `internal/database/query/` | the SQL in `internal/database/queries/`, by sqlc |

`./scripts/check.sh` regenerates it. Tool versions are the `tool` directives
in `go.mod`, so `go tool sqlc` runs the same version locally, in CI and in the
container. The same directives pin revive, Staticcheck
(`honnef.co/go/tools/cmd/staticcheck`) and the dead-code analysis
(`golang.org/x/tools/cmd/deadcode`); the check script runs all three, so none
needs a separate install.

## API documentation

`internal/web/openapi.yaml` is the API's contract, written by hand and compiled
into the binary. Every build serves it as YAML at `/api/openapi.yaml`, which
the page at `/api/docs` reads, and as JSON derived from it at
`/api/openapi.json`. It declares no `servers`: every path is the whole `/api/...`
address, combined with the origin the document was fetched from. A change to an
endpoint's contract updates this file and the route and schema tests in
`internal/web` (`apischema_test.go`, `apidocumentation_test.go`) in the same
change.

## Migrations

The schema is the [Goose](https://github.com/pressly/goose) SQL migrations under
`migrations/`, the directory the standalone Goose CLI reads; sqlc reads the same
files. Goose is a `tool` directive in `go.mod`, and both image targets carry a
PostgreSQL-only build of it at `/usr/local/bin/goose` with the files at
`/migrations`. From this directory:

```shell
go tool goose -env=none -dir migrations create <what_it_does> sql
go tool goose -env=none -dir migrations validate
```

Against a database, set `GOOSE_DRIVER=postgres`, a `GOOSE_DBSTRING` holding no
password, and `PGPASSWORD`, then run `go tool goose -env=none -dir migrations`
with `status`, `version`, `up`, `up-to`, `down`, `down-to`, `redo` or `reset`. A
deployment runs these through the Compose `migrations` service, as the
[repository README](../../README.md#the-database) describes, including what each
Down removes.

## The two builds

One Dockerfile produces both, and they differ by build tag:

| Stage | Built with | Carries |
| --- | --- | --- |
| `deployment` | no tags | no password sign-in; refuses to start with `DEBUG` set |
| `development` | `-tags=devtools` | password sign-in, with `DEBUG=true` and a loopback-only bind |

`compose.yml` selects `deployment` unless `API_BUILD_TARGET` in `.env` names the
other. Code that must not exist in a deployment lives in a file guarded by the
`devtools` tag.

Both take one build argument, `COMMIT`, linked into the binary as the version it
reports and logs and set as the image's revision label. It defaults to
`development`, which a build run by `go build` alone also reports; CI sets it to
the short commit the image is published as. It is not a runtime setting.
