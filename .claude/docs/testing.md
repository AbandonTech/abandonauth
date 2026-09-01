# Testing and validation

## Current state

The API has unit and integration tests, and CI runs the same
`./scripts/check.sh` a developer runs. Every package that contains statements is
held to 80% statement coverage, measured from a real profile; the gate fails the
run, and it currently passes.

The site has Vitest tests and a production build. There is still **no frontend
lint or typecheck command**. Do not claim one passed.

New behavior must add real automated tests. A manual request is not a
substitute. If the necessary test framework is missing, the plan must establish
it as part of the change or stop for user approval.

## Security test requirements

Auth, OAuth, token, session, redirect, credential, and authorization changes
require positive, negative, abuse-case, and regression coverage. As relevant,
cover:

- malformed, expired, future, wrong-algorithm, wrong-issuer, wrong-audience,
  wrong-token-type, and missing-claim tokens;
- exact scope and ownership checks, cross-user and cross-application access;
- state, nonce, and PKCE mismatch, expiry, replay, and concurrent consumption;
- exact callback matching and rejection of open redirects or unsafe schemes;
- one-time exchange behavior across concurrent requests and worker-safe storage;
- user, developer application, exchange, access, refresh, and session token
  separation;
- cookie attributes, CSRF rejection, logout, revocation, and rotation;
- debug-route and permissive-CORS exclusion from production configuration;
- rate limits and non-enumerating errors.

Mock provider HTTP calls and database access, or use isolated test databases.
Never use live OAuth clients or real credentials. Test output, fixtures, and
snapshots must contain placeholders only.

Build test state from what the application itself produces. A test that needs
the schema runs the migrations; it does not carry a copy of them. A checked-in
fixture that duplicates application output is a second source of truth, drifts
from the first, and outlives whatever it was copied from. Test helpers follow
the naming rules in `CLAUDE.md` in full: they describe database state by the
operation this service performs on it, never as a "prior" or "legacy" anything.

## What a test is allowed to assert

A test states the exact behaviour this service is required to have. It never
states that the service matches something else, and it never describes a
scenario that exists only because of a change in progress.

Integration tests go through the front door. `internal/web/servertest` starts
the real service against a database of its own; a test sends requests in the
order a client sends them and asserts the responses, how the request data was
handled, and the state left in the database. Its client keeps a cookie jar and
returns redirects rather than following them, because both are part of what the
endpoints promise. Providers are answered by local servers injected at
construction.

Do not assert a schema shape, a query shape, or a generated struct: those are
how today's behaviour is achieved, not what is promised. A cascade, a uniqueness
rule or an ordering is proved through the endpoint whose contract depends on it.
Do not call `query.Queries` from a test.

A few things no client can reach are tested against their service directly: a
constructor that must refuse an unusable setting, a guard that exists so a
future caller cannot get past it, and the expiry sweeps, which no endpoint
drives. Reach for this only when there is no front door to the behaviour, and
still state the requirement rather than the mechanism.

## Endpoint inputs and endpoint journeys

An endpoint that reads a body, a path value or a required query value keeps that
reading in an unexported reader beside its handler, and the reader is driven
directly by a small test: one valid request, and the invalid ones that define
that endpoint's own required members, accepted types and failure locations. The
handler calls the same reader, so the test drives what a request goes through
rather than a second description of it.

Those tests stop at the shape of a request. Whether a credential is checked
before an input is read, whether ownership is settled before a body is parsed,
and whether a request budget is spent before either, are promises about a whole
request and are proved through `servertest` against the running service.

Coverage output is for reading which of those promises nothing exercises. It is
never itself the reason for a test: nothing here tests the standard library, the
JWT or database libraries, generated code, a failure no input or dependency can
cause, or the test support.

## Available checks

Run what a change could have broken, from the repository root, and report
exactly what was run:

```text
./scripts/check.sh                 codegen, formatting, lint, both builds, unit tests
./scripts/check.sh --integration   also the race, database and coverage checks
./scripts/db.sh down               remove the test database afterwards

npm --prefix src/website test
npm --prefix src/website run build
```

On Windows, invoke them with
`& "C:\Program Files\Git\bin\bash.exe" scripts/check.sh ...`; never execute a
`.sh` file directly through PowerShell, which opens the OS application chooser.

`--integration` is authoritative for coverage and is the one to run after a
change to database or concurrency behaviour. Both images are built on every pull
request by `.github/workflows/`, which is what covers a Dockerfile change.

The coverage profile is built with `-tags=integration` and **not** `devtools`, so
a test written under `integration && devtools` earns no coverage against the
gate. That is deliberate: those files are not in the published binary.

`./scripts/check.sh` reports formatting rather than correcting it, so a check
never rewrites the worktree unannounced; `--fix-fmt` corrects it. Generated sqlc
and Swagger output is regenerated every run and is never edited.

A test that spends a request budget should hold the clock with
`servertest.WithSteadyClock()`. Budgets are counted in windows fixed to the
clock, so a slow test can otherwise build a count in one window and be measured
against the next.
