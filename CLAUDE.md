# AbandonAuth

AbandonAuth is an identity provider and OAuth application broker. It runs a
FastAPI API, a Nuxt administration and login site, and PostgreSQL through
Prisma. Authentication, authorization, token, session, redirect, credential,
and account changes are security-critical.

## Read before changing code

| Work | Read first |
| --- | --- |
| Finding code | `.claude/docs/repo-map.md` |
| Architecture or data flow | `.claude/docs/architecture.md` |
| Auth, OAuth, tokens, sessions, or secrets | `.claude/docs/security.md` |
| Tests or validation | `.claude/docs/testing.md` |
| Agent phase boundaries | `.agents/abandonauth-agent-workflow.md` |

Read the repo map before searching or launching an exploration agent. Use
targeted Glob, Grep, or direct reads after the map as tool permissions allow.
Update the map in the same change when files, routes, packages, or agent
workflow components move or change.

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
- Use database migrations for schema changes. Never use `prisma db push`
  against production or assume an empty database.
- Add negative, abuse-case, and regression tests before changing security
  semantics. Mock provider HTTP calls; never use live OAuth credentials in
  tests.

## Current validation

There is no tracked automated test suite or frontend lint/typecheck command.
Do not claim those checks passed. For relevant changes, run the checks that
exist and report the gap:

```text
poetry -C src/api run ruff check .
poetry -C src/api run pyright
npm --prefix src/website run build
docker compose config
```

The pre-commit hooks run Ruff with fixes and run Prisma format/generate. They
can modify files, so inspect the worktree before and after using them. New
behavior requires a real automated test suite or an explicit plan to establish
the missing infrastructure; manual requests are not a substitute for tests.

## Repository constraints

- Python is 3.11 with absolute imports, Ruff, and Pyright settings in
  `src/api/pyproject.toml`.
- The frontend is Nuxt 3, Vue 3, TypeScript, Tailwind, and DaisyUI.
- `src/website/package-lock.json` is tracked. Do not add or update another
  package-manager lockfile unless the user first chooses a package manager.
- Do not edit generated Prisma client code. Read `src/api/prisma/schema.prisma`
  and migrations instead.
- Keep comments focused on non-obvious security or design reasons.
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
- Comments and docstrings exist to tell the next developer something the code
  does not already say. Do not restate the signature and do not narrate
  migration history.
- Referencing an outside system is allowed only when it is an operational fact
  the code or an operator must act on, such as a provider's published endpoint,
  a database object that physically exists in production, or a wire format
  third-party callers already send.
