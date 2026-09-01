# AbandonAuth API

The identity provider and OAuth application broker. One Go program: it serves
the API, carries the schema, and runs the operational commands.

Settings, provider registration and what a deployment expects of its environment
are in the [repository README](../../README.md). This file is about working on
the API itself.

## Commands

```text
abandonauth serve                          answer API requests
abandonauth maintenance                    answer every request 503, opening no database connection
abandonauth database rotate-auth-epoch     withdraw every issued credential
```

`serve` migrates before it accepts a request, and refuses a database it cannot
prove it built. `maintenance` reads nothing but the bind address, so it starts
when the reason for a failure is the configuration itself.

## Checks

Run from the repository root, not from here:

```shell
./scripts/check.sh                 codegen, formatting, lint, both builds, unit tests
./scripts/check.sh --quick         the same, skipping codegen and go mod tidy
./scripts/check.sh --fix-fmt       format the source, then check
./scripts/check.sh --integration   also the race, database and coverage checks
./scripts/db.sh down               remove the test database afterwards
```

On Windows run them through Git Bash —
`& "C:\Program Files\Git\bin\bash.exe" scripts/check.sh` — rather than invoking
the `.sh` file from PowerShell, which opens the application chooser.

CI runs the same script, so it cannot drift from a local run. `--integration`
holds every package to 80% statement coverage.

## Generated code

Neither of these is committed, and neither is ever edited by hand:

| Output | Generated from |
| --- | --- |
| `internal/database/query/` | the SQL in `internal/database/queries/`, by sqlc |
| `docs/` | the handler annotations, by swag |

`./scripts/check.sh` regenerates both. Tool versions come from the `tool`
directives in `go.mod`, so `go tool sqlc` and `go tool swag` are the same
versions here, in CI and in the container.

## Migrations

The schema is the goose files under `internal/database/migrations/`, embedded in
the binary. There is no second description of it: no committed dump, no fixture
a test builds from.

Add one as `<UTC timestamp>_<what it does>.sql` with `-- +goose Up` and
`-- +goose Down`. Down exists for disposable test databases; a deployment never
runs it, and neither does a recovery.

The baseline writes a `schema_identity` row naming itself. A start-up requires
that marker to agree with the migration history before it will touch a database
that already holds account tables, so a hand-written history alone does not make
a schema this service will migrate.

## The two builds

One Dockerfile produces both, and they differ by build tag rather than by
configuration:

| Stage | Built with | Carries |
| --- | --- | --- |
| `deployment` | no tags | no password sign-in, and refuses to start with `DEBUG` set |
| `development` | `-tags=devtools` | password sign-in, with `DEBUG=true` and a loopback-only bind |

Both carry the documentation and the schema, which every build serves.

`compose.yml` selects `deployment` unless `API_BUILD_TARGET` in `.env` names the
other. Code that must not exist in a deployment lives in a file guarded by the
`devtools` tag, so its absence is a compile-time fact rather than a runtime
check. `swag` does not honour build tags, so the document generated from the
annotations names password sign-in either way; `internal/web/apidocumentation.go`
narrows it to what the running build serves before publishing it.

## Secrets

`DATABASE_URL`, `JWT_SECRET` and the three provider client secrets are read from
the environment only. They have no flag: an argument is readable by every
process on the machine. Everything holding one is a `config.Secret`, which does
not render its value, and no error or log line repeats one.
