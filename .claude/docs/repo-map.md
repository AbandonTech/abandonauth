# Repo map

Read this before searching. Keep it current when files, routes, packages,
services, schemas, or agent workflow components move or change.

```text
src/api/          Go API, SQL queries, and migrations
src/website/      Nuxt login and developer-application site
docs/             external provider setup guides and images
scripts/          the validation pipeline, shared by local runs and CI
.github/          CI, image builds, and Dependabot configuration
.agents/          shared planner-to-implementer workflow
.opencode/        OpenCode planner and security reviewer
.claude/          Claude implementer, skill, and repository guidance
.plans/           cross-session implementation plans
compose.yml       the stack: API, website, and PostgreSQL
compose.test.yml  the throwaway database and check container
```

## API

A `net/http` router in front of interface-backed services in front of sqlc
queries over pgx. Nothing is served that `src/api/internal/web/routes.go` does
not name, and everything it names is under `/api`, the route root. Paths below
are relative to `src/api/`.

- `go.mod` — module, pinned dependencies, `tool` directives fixing the sqlc,
  swag and revive versions
- `sqlc.yaml` — how `queries/` becomes the generated `query` package
- `revive.toml` — lint rules
- `cmd/abandonauth.go` — commands, flags, environment binding, Swagger metadata;
  secrets are environment-only and have no flag
- `cmd/operations.go` — `serve`, `maintenance`, `database rotate-auth-epoch`
- `internal/config/` — validated immutable configuration;
  `PasswordSignInEnabled`
- `internal/buildmode/` — which variant compiled, by the `devtools` tag
- `internal/logging/` — the logger; never a query string, header or cookie
- `internal/urlpolicy/` — callback URI policy and origin parsing; `Callback`
  keeps the registered spelling beside the parsed form

### Database

- `internal/database/migrations/` — embedded goose migrations: baseline schema
  and its `schema_identity` marker, then auth state, sessions, revocation, rate
  limits
- `internal/database/queries/` — the SQL source; edit this, never generated code
- `internal/database/query/` — sqlc output: gitignored, regenerated every run
- `internal/database/pool.go` — connection pool lifecycle
- `internal/database/migrate.go` — the embedded runner; inspects and migrates
  under one advisory lock
- `internal/database/schemastate.go` — what a database looks like untouched, and
  which states may be migrated
- `internal/database/authorityrotation.go` — `rotate-auth-epoch`: every token,
  state, code and session invalidated in one transaction
- `internal/database/testdatabase/` — a migrated database per test

`RotateAuthority` is proved twice: against the database in
`internal/database/authorityrotation_integration_test.go`, and through the
endpoints that stop accepting credentials in
`internal/web/authorityrotation_integration_test.go`.

### Services

- `internal/services/keyring/` — per-purpose keys derived from the signing root
- `internal/services/tokens/` — issues and validates the two access token
  classes
- `internal/services/credentials/` — bcrypt hashing, random credentials;
  `Hasher` carries the work factor, and the minimum-cost constructor exists only
  under the `integration` tag
- `internal/services/accounts/` — resolves a provider identity to a user,
  creating one atomically
- `internal/services/applications/` — developer applications, credentials,
  callback URIs
- `internal/services/oauth/` — authorization state with PKCE, one-time exchange
  codes
- `internal/services/sessions/` — browser sessions and their CSRF tokens
- `internal/services/authority/` — the auth epoch every check is measured
  against
- `internal/services/ratelimit/` — fixed-window budgets, keyed so a public
  identifier cannot lock anyone out
- `internal/services/housekeeping/` — expiry sweeps on a ticker `serve` owns:
  logins, codes, sessions, withdrawals, budget windows
- `internal/services/providers/` — Discord, GitHub and Google clients against
  fixed HTTPS endpoints
- `internal/services/providers/providertest/` — local servers answering as the
  providers; no test leaves the machine

### Web

- `internal/web/routes.go` — the route table: `APIRoot` and every URL, once
- `internal/web/handlers.go` — binds each route name to its handler
- `internal/web/server.go` — composition, middleware order, deadlines; the
  credential hasher the services and the password handler share
- `internal/web/requesttarget.go` — the one spelling of a target that is served
- `internal/web/index.go` — `GET /api`, `GET /api/`
- `internal/web/currentuser.go` — `GET /api/me`
- `internal/web/userapplications.go` — `GET /api/user/applications`
- `internal/web/login.go` — `POST /api/login`, spending an exchange code
- `internal/web/burntoken.go` — `POST /api/burn-token`
- `internal/web/developerapplication.go` — the seven
  `/api/developer_application` routes
- `internal/web/providerlogin.go` — `GET /api/ui/{provider}/authorize`
- `internal/web/providercallback.go` — the Discord, GitHub, Google callbacks
- `internal/web/browsersession.go` — `/api/ui/`, `POST /api/ui/logout`, session
  and CSRF checks
- `internal/web/authentication.go` — bearer and session authorization per route
- `internal/web/cors.go` — exactly one permitted origin, declared addresses only
- `internal/web/middleware.go` — panic recovery, request identifiers, request log
- `internal/web/requestlimit.go` — applies the budgets
- `internal/web/maintenance.go` — the static 503 a failed deployment serves
- `internal/web/apidocumentation.go` — `/api/docs`, `/api/docs/`,
  `/api/docs/oauth2-redirect`, `/api/openapi.json`, and the narrowing to what
  this build serves
- `internal/web/models/` — request and response bodies
- `internal/web/request/`, `internal/web/response/` — input reading, answer
  shapes
- `internal/web/servertest/` — the real service against its own database; tests
  give the path below the route root, and `AtExactTarget` writes a target in
  full; `credentialhasher_*.go` chooses the work factor the service under test
  stores credentials at
- `internal/web/testdata/` — the API schema the service must publish

Files ending `_devtools.go` compile only with `-tags=devtools`: password
sign-in, absent from a deployment. A test in one of them is named
`TestDevtools...`, which is how a run selects the tests only that build carries.

An endpoint that reads structured input keeps that reading in an unexported
reader beside its handler. `<endpoint>_test.go` drives the reader;
`<endpoint>_integration_test.go` holds the complete request journeys.

## Website

Paths are relative to `src/website/`. Everything the browser runs is under
`app/`, which is what `~` names.

- `package.json` — scripts and dependencies; npm and `package-lock.json` are
  canonical
- `nuxt.config.ts` — the development forwarder, Tailwind, public runtime
  settings
- `vitest.config.ts` — test settings; `// @vitest-environment nuxt` opts into a
  real Nuxt runtime
- `test/` — the site's tests
- `server/api/[...].ts` — forwards `/api/**` to the API, path unchanged
- `server/utils/apiProxy.ts` — where a forwarded call goes, what the development
  forwarder targets, why redirects go back to the browser
- `server/utils/siteCallback.ts` — where the site's own sign-in returns the
  browser
- `app/utils/providerLogin.ts` — the address that asks the API to start a
  sign-in
- `app/utils/browserSession.ts` — CSRF header, session paths, signed-in check
- `app/middleware/auth.global.ts` — route gate; asks `/api/me`
- `app/pages/login.vue` — the provider sign-in buttons
- `app/pages/developer-applications/` — developer application and callback URI
  administration
- `app/layouts/dashboard.vue` — authenticated layout, including logout
- `app/components/` — shared Vue components
- `app/types/` — user and developer application DTOs
- `app/assets/css/main.css` — stylesheet entrypoint, theme tokens, daisyUI
  themes

The site holds no access token: it sends the session cookie the API set, copies
the readable CSRF cookie into `X-CSRF-Token` on writes, and builds no provider
address. `/api` is the API's route root, so a browser's path is forwarded whole.

## Data

`internal/database/migrations/` defines `User`, the provider accounts,
`PasswordAccount`, `DeveloperApplication` and `CallbackUri`, then the auth
epoch, OAuth state, exchange codes, browser sessions, JWT revocations and rate
limit buckets. Provider accounts are one-to-one with users; users own developer
applications; callback URIs belong to applications. Passwords and developer
credentials are stored only as hashes, every one-time credential only as a
domain-separated hash.

Table and column identifiers are quoted and mixed case. Renaming them would
rewrite live data for no functional gain and is deliberately out of scope.

## Validation

- `./scripts/check.sh` — codegen, formatting, tidiness, both builds, revive, vet
  on every tag set, the test matrix, then the deployment suite and the
  `^TestDevtools` selection
- `./scripts/check.sh --integration` — the same up to the matrix, then those two
  runs in a container with race detection, a database and coverage
- `./scripts/testmatrix.sh` — the inventory each build's run must contain, and
  the tag sets the inexpensive credential hasher may be compiled into
- `./scripts/containercheck.sh` — what runs inside the container, and the
  coverage gate
- `./scripts/db.sh up` / `down` — the throwaway database

Each test function runs once per invocation: the deployment build carries the one
complete suite, and the devtools build runs only the tests that exist for it.
`go test -race` links a C runtime, so the race, integration and coverage checks
run only in the container; nothing here needs a C compiler on the host. When to
run which, and what to report, is in `.claude/docs/testing.md`.

## Tooling and CI

- `src/api/Dockerfile` — one build, two runtime targets: `deployment` (default)
  and `development`
- `Dockerfile.test` — the image the container checks run in
- `.pre-commit-config.yaml` — whitespace checks and `scripts/check.sh`
- `.github/workflows/check.yml` — the check pipeline, and the site's tests and
  build
- `.github/workflows/linting.yml` — pre-commit, skipping the hook `check.yml`
  runs
- `.github/workflows/` — image build and publish, push and pull-request entry
  points
- `.github/dependabot.yml` — dependency updates

The published deployment image carries no password sign-in, refuses
`DEBUG=true`, runs as an account that is not root, and holds only the binary and
a certificate bundle; it does carry the documentation and schema every build
serves. `compose.yml` builds it unless `API_BUILD_TARGET` in `.env` names the
`development` target, the variant the password routes compile into. Both images
are built on every pull request by `.github/workflows/`.

## Documentation and agent tooling

Each subject has one owner; everything else links to it.

- `CLAUDE.md` — entry point: required reading, repository constraints, naming
  and comment rules
- `.agents/abandonauth-agent-workflow.md` — authorization, roles, plan contract,
  security classification and review, plan lifecycle
- `.claude/docs/repo-map.md` — this inventory
- `.claude/docs/architecture.md` — how the parts fit and how a sign-in travels
  through them
- `.claude/docs/security.md` — security requirements, the controls in force,
  where their negative tests are
- `.claude/docs/testing.md` — what a test may assert, and the checks to run
- `.opencode/agent/abandonauth-planner.md` — planner permissions and bootstrap
- `.opencode/agent/abandonauth-security-reviewer.md` — reviewer permissions,
  bootstrap, output contract
- `.claude/agents/abandonauth-implementer.md` — implementer tools and refusal
  gates
- `.claude/skills/implement-plan/SKILL.md` — user-only invocation, plan-path
  validation
- `README.md` — integrating an application, running the service, local
  development
- `src/api/README.md` — the API's commands, checks, codegen, migrations, builds
- `docs/DISCORD-OAUTH2.md`, `GITHUB-OAUTH2.md`, `GOOGLE-OAUTH2.md` — registering
  with each provider
