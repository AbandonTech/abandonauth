# AbandonAuth

AbandonAuth is an identity provider and OAuth application broker: a Go API, a
Nuxt administration and login site, and PostgreSQL. Authentication,
authorization, token, session, redirect, credential, and account changes are
security-critical.

## Read before changing code

| Work | Read first |
| --- | --- |
| Finding code | `.claude/docs/repo-map.md` |
| Architecture or data flow | `.claude/docs/architecture.md` |
| Auth, OAuth, tokens, sessions, or secrets | `.claude/docs/security.md` |
| Tests or validation | `.claude/docs/testing.md` |
| Agent phase boundaries | `.agents/abandonauth-agent-workflow.md` |

Read the repo map before searching or launching an exploration agent, then use
targeted Glob, Grep, or direct reads as tool permissions allow. Update the map
in the same change when files, routes, packages, or agent workflow components
move or change.

## Workflow

Non-trivial work uses two separate sessions. OpenCode's `abandonauth-planner`
investigates, resolves every material question, obtains the required security
review, and writes `.plans/<feature>.md`; the user then starts a fresh Claude
Code session and runs `/implement-plan .plans/<feature>.md`. Plan approval,
agent completion, or leaving plan mode does not authorize implementation; that
invocation does. The rules are in `.agents/abandonauth-agent-workflow.md` →
"Authorization".

## Security

`.claude/docs/security.md` is canonical. Read "Secrets", "OAuth and OIDC",
"Tokens and sessions", and "Authorization and abuse controls" before changing
any of them, and "The controls in force, and where they live" before weakening
one. Universally: never read, print, transmit, or commit a real `.env` file,
key, credential, token, cookie, or JWT, and use `.env.sample` placeholders;
never put a secret in a log, URL, error, fixture, plan, commit, or chat message;
fail closed; compare authorization and scopes exactly; and treat protocol and
credential behaviour as explicit decisions rather than provider defaults.

## Validation

Run what a change could have broken and report exactly what was run, never
claiming an unrun check passed. The commands, the Windows invocation, the
coverage gate and the frontend gap are in `.claude/docs/testing.md` →
"Available checks"; what a test must cover is in "Security coverage" and "What a
test is allowed to assert". New behaviour requires automated tests; a manual
request is not a substitute.

## Repository constraints

- The API is Go, with the toolchain, dependency and tool versions pinned in
  `src/api/go.mod`. Lint rules are in `src/api/revive.toml`.
- The frontend is Nuxt 4, Vue 3, TypeScript, Tailwind, and DaisyUI.
  `src/website/package-lock.json` is tracked; do not add or update another
  package-manager lockfile unless the user first chooses a package manager.
- Generated code is not committed and is never edited: sqlc output under
  `src/api/internal/database/query/` and Swagger output under `src/api/docs/`.
  Change the SQL in `internal/database/queries/` or the handler annotations, and
  regenerate.
- The schema is the goose migrations under
  `src/api/internal/database/migrations/`, embedded in the binary; do not add a
  second description of it. Change a schema only by migration. Never push a
  schema at a production database, never migrate one down there, and never
  assume a database is empty.
- Two API builds come from one Dockerfile. The published `deployment` target
  carries no password sign-in; the `development` target is built with
  `-tags=devtools` and carries it. Code that must not exist in a deployment
  lives in a file guarded by that tag. Both carry the documentation and the
  schema, which every build serves.
- Preserve unrelated user changes and ignored local configuration.

## Naming and documentation

These rules apply to source, file and directory names, identifiers, comments,
docstrings, tests, fixtures, commit messages, plans, and repository docs.

- Never name a thing after the framework, language, or implementation it came
  from or is replacing. There is no `fastapi`, `prisma`, `python`, `legacy`,
  `old`, `new`, `v2`, or `compat` in a name unless that string is a literal
  external identifier the code must match.
- Temporal framing is the same violation wearing a different word: `prior`,
  `previous`, `earlier`, `former`, `original`, and `pre-<anything>` are not
  permitted either. There is one schema, one set of migrations, one API: this
  application's. A name implying a second, older one asserts that this code is a
  successor rather than the thing itself, and that framing becomes permanent.
- Never describe current behaviour by reference to a removed or replaced
  implementation. Describe what the code does and why, in this application's own
  domain. Code being deleted must not survive as a reference point in the code
  that replaces it.
- Name the state of an external system after the operation this application
  performs on it, not after whatever produced that state. A database whose
  schema this service cannot prove it built is `unrecognised`, because
  recognising one is this application's own operation.
- Do not add a test fixture that duplicates something the application already
  produces. If a test needs a schema the migrations build, run the migrations. A
  copied fixture is a second source of truth that drifts and outlives the thing
  it was copied from.
- Name a file after the concept it defines. Vague names such as `contract.go`,
  `helpers.go`, `utils.go`, `common.go`, or `misc.go` are not acceptable.
- Reference an outside system only where it is an operational fact the code or
  an operator must act on: a provider's published endpoint, a database object
  that physically exists in production, or a wire format third-party callers
  already send.

## Comments

A comment earns its place only by saying something the code cannot. The default
is no comment, in source, configuration, Dockerfiles, compose files, shell
scripts, and workflow files alike.

- Write a comment only for a `why` a reader cannot recover from the code: a
  non-obvious constraint, a subtle failure mode, a security rule, a line that
  looks wrong until it is explained. Never restate what the line, the signature,
  the flag, or the file name already says.
- Configuration describes itself. A compose service, a Dockerfile stage, a
  workflow step, or an ignore rule gets no comment saying what it configures,
  and a file that starts a database gets none saying it starts a database.
- One or two lines. Rationale needing a paragraph belongs in `.claude/docs/` or
  in a plan.
- No orientation prose: no header summarising the file, no narration of the next
  block, no note describing what is absent.
- Go doc comments on exported identifiers are required by revive. Keep them to
  one sentence unless a security constraint needs a second.
- Do not narrate migration history.
- A comment that is no longer true is worse than no comment. When the code
  moves, the comment moves or goes.
