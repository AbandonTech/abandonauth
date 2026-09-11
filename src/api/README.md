# AbandonAuth API

The identity provider and OAuth application broker. One Go program: it serves
the API, carries the schema, and runs the operational commands.

Settings, provider registration, deployment and the check commands are in the
[repository README](../../README.md).

## Commands

```text
abandonauth serve                          answer API requests
abandonauth maintenance                    answer every request 503, opening no database connection
abandonauth database rotate-auth-epoch     withdraw every issued credential
```

## Generated code

Neither of these is committed, and neither is edited by hand:

| Output | Generated from |
| --- | --- |
| `internal/database/query/` | the SQL in `internal/database/queries/`, by sqlc |
| `docs/` | the handler annotations, by swag |

`./scripts/check.sh` regenerates both. Tool versions are the `tool` directives
in `go.mod`, so `go tool sqlc` and `go tool swag` run the same versions locally,
in CI and in the container.

## Migrations

The schema is the [goose](https://github.com/pressly/goose) migrations under
`internal/database/migrations/`, embedded in the binary. goose is a `tool`
directive in `go.mod`. To add one:

```shell
go tool goose -dir internal/database/migrations create <what_it_does> sql
```

## The two builds

One Dockerfile produces both, and they differ by build tag:

| Stage | Built with | Carries |
| --- | --- | --- |
| `deployment` | no tags | no password sign-in; refuses to start with `DEBUG` set |
| `development` | `-tags=devtools` | password sign-in, with `DEBUG=true` and a loopback-only bind |

`compose.yml` selects `deployment` unless `API_BUILD_TARGET` in `.env` names the
other. Code that must not exist in a deployment lives in a file guarded by the
`devtools` tag.
