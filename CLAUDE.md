# AbandonAuth

AbandonAuth is an identity provider and OAuth application broker. It runs a Go
API, a Nuxt administration and login site, and PostgreSQL. Authentication,
authorization, token, session, redirect, credential, and account changes are
security-critical.

## Read before changing code

| Work | Read first |
| --- | --- |
| Finding code | `.claude/docs/repo-map.md` |
| Architecture or data flow | `.claude/docs/architecture.md` (stale; see below) |
| Auth, OAuth, tokens, sessions, or secrets | `.claude/docs/security.md` (stale; see below) |
| Tests or validation | `.claude/docs/testing.md` |
| Agent phase boundaries | `.agents/abandonauth-agent-workflow.md` |

Read the repo map before searching or launching an exploration agent. Use
targeted Glob, Grep, or direct reads after the map as tool permissions allow.
Update the map in the same change when files, routes, packages, or agent
workflow components move or change.

`architecture.md` and `security.md` still describe an implementation this
service no longer has. Read the code, not them, until they are rewritten;
`.plans/migrate-fastapi-backend-to-go.progress.md` says when that happens.

## Workflow

Non-trivial work uses two separate sessions:

1. OpenCode's `abandonauth-planner` investigates, resolves material questions,
   performs the required security review, and writes `.plans/<feature>.md`.
2. After approval, start a fresh Claude Code session and explicitly run
   `/implement-plan .plans/<feature>.md`.

Planning and implementation are mandatory workflow boundaries. Plan approval,
agent completion, or leaving plan mode does not authorize implementation. The
user's own `/implement-plan` invocation does, and the implementer must accept
it as such rather than demanding further proof of user intent or session
freshness, which its forked context cannot show. OpenCode permissions enforce
the planning role; `disable-model-invocation` on the skill enforces that only
the user can start implementation. Detailed rules live in
`.agents/abandonauth-agent-workflow.md`.

## Security rules

- Never read, print, transmit, copy, or commit real `.env` files, private keys,
  credentials, authorization codes, passwords, provider access tokens, refresh
  tokens, session cookies, or JWTs. Use `.env.sample` placeholders.
- Never log or place secrets or tokens in URLs, errors, telemetry, fixtures,
  snapshots, plans, commits, or chat output.
- Treat OAuth state, nonce, PKCE, redirect URI matching, issuer, audience,
  algorithm, token type, replay prevention, expiration, rotation, revocation,
  cookie attributes, CSRF, rate limits, and account linking as explicit design
  decisions. Do not rely on provider defaults.
- Fail closed. Debug authentication routes and permissive CORS must not be
  reachable through production configuration mistakes.
- Use exact authorization and scope comparisons. Keep user, developer
  application, exchange, access, refresh, and session credentials distinct.
- Use database migrations for schema changes. Never push a schema at a
  production database, never run a migration down there, and never assume the
  database is empty.
- Add negative, abuse-case, and regression tests before changing security
  semantics. Mock provider HTTP calls; never use live OAuth credentials in
  tests.

## Current validation

One script covers the API, and CI runs the same one, so local and CI cannot
drift. Run what a change could have broken and report exactly what you ran:

```text
./scripts/check.sh                 codegen, formatting, lint, both builds, unit tests
./scripts/check.sh --integration   also the race, database and coverage checks
./scripts/check.sh --images        also both images and the composed stack
./scripts/db.sh down               remove the test database afterwards

npm --prefix src/website test
npm --prefix src/website run build
```

`--integration` and `--images` need Docker and take minutes; the default run
does not. `./scripts/check.sh` reports formatting rather than correcting it, and
`--fix-fmt` corrects it, so a check never rewrites the worktree unannounced.

The 80% per-package coverage gate is not currently met. Do not describe a run as
passing when it failed there.

There is still no frontend lint or typecheck command. Do not claim one passed;
Vitest and the production build are the site's validation.

New behavior requires tests. A manual request is not a substitute for one.

## Repository constraints

- The API is Go, with the toolchain, dependency and tool versions pinned in
  `src/api/go.mod`. Lint rules are in `src/api/revive.toml`.
- The frontend is Nuxt 4, Vue 3, TypeScript, Tailwind, and DaisyUI.
- `src/website/package-lock.json` is tracked. Do not add or update another
  package-manager lockfile unless the user first chooses a package manager.
- Generated code is not committed and is never edited: the sqlc output under
  `src/api/internal/database/query/` and the Swagger output under
  `src/api/docs/`. Change the SQL in `internal/database/queries/` or the handler
  annotations instead, and regenerate.
- The schema is the goose migrations under
  `src/api/internal/database/migrations/`, embedded in the binary. Do not add a
  second description of it.
- Two API builds come from one Dockerfile. The `deployment` target is what is
  published and carries neither password sign-in nor the documentation UI; the
  `development` target is built with `-tags=devtools` and carries both. Code that
  must not exist in a deployment lives in a file guarded by that tag.
- Preserve unrelated user changes and ignored local configuration.

## Naming and documentation

These rules apply to source, file and directory names, identifiers, comments,
docstrings, tests, fixtures, commit messages, plans, and repository docs.

- Never name a thing after the framework, language, or implementation it came
  from or is replacing. There is no `fastapi`, `prisma`, `python`, `legacy`,
  `old`, `new`, `v2`, or `compat` in a name unless that string is a literal
  external identifier the code must match.
- Temporal framing is the same violation wearing a different word. `prior`,
  `previous`, `earlier`, `former`, `original`, and `pre-<anything>` are not
  permitted either. There is one schema, one set of migrations, one API: this
  application's. A name that implies a second, older one asserts that this code
  is a successor rather than the thing itself, and that framing becomes
  permanent.
- Never describe current behavior by reference to a removed or replaced
  implementation. Describe what the code does and why, in terms of this
  application's own domain. Code that is being deleted must not survive as a
  reference point in the code that replaces it.
- Name the state of an external system after the operation this application
  performs on it, not after whatever produced that state. A database this
  service has not taken ownership of is `unadopted`, because `adopt` is this
  application's own operation; it is not a "prior" or "legacy" database.
- Do not add a test fixture that duplicates something the application already
  produces. If a test needs a schema the migrations build, run the migrations.
  A copied fixture is a second source of truth that drifts and outlives the
  thing it was copied from.

## Comments

A comment earns its place only by saying something the code cannot. The default
is no comment. This applies to source, configuration, Dockerfiles, compose
files, shell scripts, and workflow files alike.

- Write a comment only for a `why` a reader cannot recover from the code: a
  non-obvious constraint, a subtle failure mode, a security rule, a line that
  looks wrong until it is explained. Never restate what the line, the
  signature, the flag, or the file name already says.
- Configuration describes itself. A compose service, a Dockerfile stage, a
  workflow step, or an ignore rule does not get a comment saying what it
  configures, and a file that starts a database does not get a comment
  explaining that it starts a database.
- One or two lines. Rationale that needs a paragraph belongs in `.claude/docs/`
  or in a plan, not in the file.
- Do not write orientation prose: no header summarising the file, no narration
  of what the next block does, no note describing what is absent.
- Go doc comments on exported identifiers are required by revive. Keep them to
  one sentence unless a security constraint needs the second.
- Do not narrate migration history, and do not describe current behaviour by
  reference to a removed implementation.
- A comment that is no longer true is worse than no comment. When the code
  moves, the comment moves or goes.

## Testing

Tests state the exact behaviour this service is required to have. They never
state that it matches something else, and they never describe a scenario that
only exists because of a change in progress.

- Integration tests drive endpoints. They send requests, in the order a client
  sends them, and assert the responses, how the request data was handled, and
  the state the database is left in. Use `internal/web/servertest`.
- No test asserts a schema shape, a query shape, or a generated struct. Those
  are how the behaviour is achieved today, not what is promised. Prove a
  cascade, a uniqueness rule, or an ordering through the endpoint whose
  contract depends on it.
- No test exercises a replaced implementation, or the act of migrating to this
  one. `internal/database/adoption` is the single bounded exception: it is the
  one-time cutover procedure, its tests live with it, and both are deleted when
  the cutover completes.
- Name a file after the concept it defines. Vague names such as `contract.go`,
  `helpers.go`, `utils.go`, `common.go`, or `misc.go` are not acceptable.
- Referencing an outside system is allowed only when it is an operational fact
  the code or an operator must act on, such as a provider's published endpoint,
  a database object that physically exists in production, or a wire format
  third-party callers already send.
