# Repo map

Read this before searching. Keep it current when files, routes, packages,
services, schemas, or agent workflow components move or change.

```text
src/api/          FastAPI API and Prisma schema/migrations
src/website/      Nuxt login and developer-application site
docs/             external provider setup guides and images
.github/          CI, image builds, and Dependabot configuration
.agents/          shared planner-to-implementer workflow
.opencode/        OpenCode planner and security reviewer
.claude/          Claude implementer, command, and repository guidance
.plans/           cross-session implementation plans
compose.yml       local API, website, and PostgreSQL orchestration
```

## API

| Path | Holds |
| --- | --- |
| `src/api/pyproject.toml` | Python 3.11 dependencies, Ruff, Pyright, and the currently broken `dev` script target |
| `src/api/poetry.lock` | locked Python dependencies |
| `src/api/Dockerfile` | API image and Uvicorn startup |
| `src/api/abandonauth/main.py` | FastAPI app, CORS, router mounting, and Prisma lifecycle |
| `src/api/abandonauth/settings.py` | typed environment settings, including all runtime secrets |
| `src/api/abandonauth/database.py` | shared Prisma client |
| `src/api/abandonauth/models/` | auth, provider, developer-application, and user DTOs |
| `src/api/abandonauth/dependencies/services.py` | user lookup and exchange-token conversion |
| `src/api/abandonauth/dependencies/auth/hash.py` | password and developer credential hashing |
| `src/api/abandonauth/dependencies/auth/jwt.py` | JWT issue/decode, bearer dependencies, scopes, and in-memory exchange-token cache |
| `src/api/abandonauth/dependencies/auth/developer_application_deps.py` | developer application credential authentication |
| `src/api/prisma/schema.prisma` | PostgreSQL models and relationships |
| `src/api/prisma/migrations/` | existing database migration history |

### API routers

| Path | Routes or responsibility |
| --- | --- |
| `routers/__init__.py` | router registry; includes password routes only when `DEBUG` is true |
| `routers/index.py` | `/`, `/me`, `/user/applications`, `/login`, `/burn-token` |
| `routers/developer_application.py` | developer application creation, credentials, ownership, callback URIs, and deletion |
| `routers/ui.py` | UI session handoff and Discord/GitHub OAuth callbacks |
| `routers/discord.py` | Discord code exchange and account lookup/link creation helper |
| `routers/github.py` | GitHub code exchange and account lookup/link creation helper |
| `routers/google.py` | Google callback, account lookup/link creation, and redirect |
| `routers/password_login.py` | debug-only test-user creation and password login |

Routers currently call Prisma models directly. Do not invent a service layer in
a narrow change; architecture changes require an explicit plan and tests.

## Website

| Path | Holds |
| --- | --- |
| `src/website/package.json` | Nuxt scripts and dependencies; npm is represented by the tracked lockfile |
| `src/website/package-lock.json` | canonical tracked frontend lockfile |
| `src/website/nuxt.config.ts` | dev proxy and public OAuth/login runtime configuration |
| `src/website/server/api/[...].ts` | Nitro proxy from `/api/**` to the API |
| `src/website/middleware/auth.global.ts` | client-side cookie-presence route gate |
| `src/website/pages/login.vue` | Discord/GitHub authorization URL construction |
| `src/website/pages/developer-applications/` | developer application and callback URI administration |
| `src/website/layouts/dashboard.vue` | authenticated site layout |
| `src/website/components/` | shared Vue components |
| `src/website/types/` | frontend user and developer application DTOs |
| `src/website/assets/css/main.css` | Tailwind CSS entrypoint |

## Data and deployment

`src/api/prisma/schema.prisma` defines `User`, provider accounts,
`PasswordAccount`, `DeveloperApplication`, and `CallbackUri`. Provider accounts
are one-to-one with users. Users own developer applications, and callback URIs
belong to applications. Passwords and developer refresh tokens are stored as
hashes.

`compose.yml` starts the API, website, and PostgreSQL. Its Prisma bind mount
currently points at the empty root `prisma/` directory instead of
`src/api/prisma/`; do not assume Compose migrations work until that is fixed.

## Tooling and CI

| Path | Holds |
| --- | --- |
| `.pre-commit-config.yaml` | whitespace checks plus mutating Ruff, Prisma format/generate, and Pyright hooks |
| `.github/workflows/linting.yml` | reusable API lint workflow |
| `.github/workflows/build_api.yml` | API container build/publish workflow |
| `.github/workflows/build_frontend.yml` | website container build/publish workflow |
| `.github/workflows/pull_request.yml` | PR lint and image builds |
| `.github/workflows/main.yml` | main-branch lint and image publication |
| `.github/dependabot.yml` | GitHub Actions and Python dependency updates |

There is no tracked automated test suite and no frontend lint or typecheck
script. See `.claude/docs/testing.md` before claiming validation.
