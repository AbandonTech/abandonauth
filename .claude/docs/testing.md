# Testing and validation

## Current state

There is no tracked automated test suite, pytest dependency, frontend test
runner, frontend lint command, or frontend typecheck command. CI lints the API
and builds containers but does not run behavior tests. Never report tests as
passing when none exist.

New behavior must add real automated tests. If the necessary test framework is
missing, the plan must establish it as part of the change or explicitly stop
for user approval rather than substituting manual API requests.

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

Mock HTTPX provider calls and database access or use isolated test databases.
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

`internal/database/adoption` is the single exception, and a bounded one. It is
the one-time procedure for taking ownership of a database this service did not
migrate, it is the only place that names an artifact of the tool that built the
deployed database, and it is deleted together with its tests once the cutover is
complete.

## Available checks

Run relevant checks from the repository root:

```text
poetry -C src/api run ruff check .
poetry -C src/api run pyright
npm --prefix src/website run build
docker compose config
```

Run API checks for Python or Prisma changes, the website build for frontend
changes, and Compose validation for deployment changes. Documentation-only
agent setup does not require application builds.

`.pre-commit-config.yaml` contains mutating hooks: Ruff runs with fixes, Prisma
formats and generates, and whitespace hooks rewrite files. Inspect `git status`
and the diff before and after invoking pre-commit. Do not treat generated Prisma
client output as source or edit it manually.
