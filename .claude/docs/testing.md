# Testing and validation

## Current state

The API has unit and integration tests, and CI runs the same
`./scripts/check.sh` a developer runs. Every package containing statements is
held to 80% statement coverage, measured from a real profile; the gate fails the
run, and it currently passes.

The site has Vitest tests and a production build. There is still **no frontend
lint or typecheck command**. Do not claim one passed.

New behaviour must add real automated tests; a manual request is not a
substitute. If the necessary test framework is missing, the plan establishes it
as part of the change or stops for user approval.

## Security coverage

Auth, OAuth, token, session, redirect, credential and authorization changes need
positive, negative, abuse-case and regression tests for the requirements in
`.claude/docs/security.md` → "OAuth and OIDC", "Tokens and sessions" and
"Authorization and abuse controls", and extend the files that document lists
under "Where the negative tests are".

Mock provider HTTP calls and database access, or use isolated test databases.
Never use a live OAuth client or a real credential. Test output, fixtures and
snapshots contain placeholders only.

Build test state from what the application itself produces: a test that needs
the schema runs the migrations rather than carrying a copy of them. A checked-in
fixture duplicating application output is a second source of truth, drifts from
the first, and outlives whatever it was copied from. Test helpers follow
`CLAUDE.md` → "Naming and documentation" in full, and describe database state by
the operation this service performs on it, never as a "prior" or "legacy"
anything.

## What a test is allowed to assert

A test states the exact behaviour this service is required to have. It never
states that the service matches something else, and never describes a scenario
that exists only because of a change in progress.

Integration tests go through the front door. `internal/web/servertest` starts
the real service against a database of its own; a test sends requests in the
order a client sends them and asserts the responses, how the request data was
handled, and the state left in the database. Its client keeps a cookie jar and
returns redirects rather than following them, because both are part of what the
endpoints promise. Providers are answered by local servers injected at
construction.

Do not assert a schema shape, a query shape or a generated struct: those are how
today's behaviour is achieved, not what is promised. Prove a cascade, a
uniqueness rule or an ordering through the endpoint whose contract depends on
it, and do not call `query.Queries` from a test.

A few things no client can reach are tested against their service directly: a
constructor that must refuse an unusable setting, a guard that exists so a
future caller cannot get past it, and the expiry sweeps, which no endpoint
drives. Reach for this only when there is no front door, and still state the
requirement rather than the mechanism.

## Endpoint inputs and endpoint journeys

An endpoint that reads a body, a path value or a required query value keeps that
reading in an unexported reader beside its handler, driven directly by a small
test: one valid request, and the invalid ones that define that endpoint's
required members, accepted types and failure locations. The handler calls the
same reader, so the test drives what a request goes through rather than a second
description of it.

Those tests stop at the shape of a request. Whether a credential is checked
before an input is read, ownership settled before a body is parsed, or a request
budget spent before either, are promises about a whole request, proved through
`servertest` against the running service.

Coverage output is for reading which of those promises nothing exercises. It is
never itself the reason for a test: nothing here tests the standard library, the
JWT or database libraries, generated code, a failure no input or dependency can
cause, or the test support.

## Available checks

Run what a change could have broken, from the repository root, and report
exactly what was run:

```text
./scripts/check.sh                 codegen, formatting, lint, both builds, unit tests
./scripts/check.sh --integration   the tests in a container instead: integration, race, database, coverage
./scripts/db.sh down               remove the test database afterwards

npm --prefix src/website test
npm --prefix src/website run build
```

On Windows, invoke them with
`& "C:\Program Files\Git\bin\bash.exe" scripts/check.sh ...`; never execute a
`.sh` file directly through PowerShell, which opens the OS application chooser.

`--integration` is authoritative for coverage, and is required after a change to
an integration test, to `internal/database/testdatabase`, to
`internal/web/servertest`, or to the container check scripts. Both images are
built on every pull request by `.github/workflows/`, which is what covers a
Dockerfile change.

Each test function runs once per invocation. The deployment build runs the one
complete suite; the devtools build runs only `^TestDevtools`, the tests that
exist because it carries password sign-in. `scripts/check.sh` runs the two on the
host, `--integration` runs them in the container under the race detector with a
database, and `scripts/testmatrix.sh` fails the run when the set the devtools
build adds is not exactly the set that selector picks. A development-only test
therefore has to be both `devtools`-constrained and named `TestDevtools...`, and
a test written for both builds must not carry that prefix.

The coverage profile is built with `-tags=integration` and **not** `devtools`,
so a test written under `integration && devtools` earns no coverage against the
gate; deliberately, since those files are not in the published binary.

`internal/web/servertest` stores credentials at bcrypt's minimum cost. The
constructor for it is compiled only under the `integration` tag, so nothing a
deployment or a development binary can build reaches it, and the deployed work
factor is asserted separately in
`internal/services/credentials/credentials_test.go`. Hashing under test is still
bcrypt and still refuses a secret it was not made from; do not replace it with a
stub.

`./scripts/check.sh` reports formatting rather than correcting it, so a check
never rewrites the worktree unannounced; `--fix-fmt` corrects it. Generated sqlc
and Swagger output is regenerated every run and is never edited.

A test that spends a request budget should hold the clock with
`servertest.WithSteadyClock()`: budgets are counted in windows fixed to the
clock, so a slow test can otherwise build a count in one window and be measured
against the next.
