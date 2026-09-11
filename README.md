# Auth(entication)

Authentic Auth Service... Provides identification of a user from multiple external services.

Currently supported:
- Discord
- GitHub
- Google

- [Integrating your application](#integrating-your-application): signing
  people in to your application with AbandonAuth.
- [Running AbandonAuth](#running-abandonauth): deploying this service.
- [Local development](#local-development): changing this repository.

# Integrating your application

## Register a developer application

1. Login to [AbandonAuth](https://auth.abandontech.cloud)
2. Create a Developer Application
   1. Navigate to `Developer Applications`
   2. Click `Create a new application`, then click `Create Application`
   3. Take note of/save your application token as it will never be visible again (you can reset it anytime)
3. Navigate back to `Developer Applications` and click on the recently created app's UUID to edit it then click `Edit Callback URIs`. The callback URI you specify is where AbandonAuth will redirect users after authenticating. It should be whichever address your server is using to finish handling the login process.  Some examples are as follows:
   1. For local dev, `http` is accepted only on the loopback interface and only with a port: `"http://localhost:8001/login/abandonauth-callback"`
   2. Everywhere else the callback must be `https`, such as `https://mc.abandonauth.cloud/api/callback`
   ![Callback URIs](./docs/imgs/callback-uris-example.png)
4. Configure *your* application to use your developer application ID and secret to authenticate users from AbandonAuth.

## What a callback URI may be

A callback is matched exactly, so register the address you will actually be
returned to. It must be absolute, and:

- `https` anywhere; `http` only when the host is loopback, and then it must
  state a port;
- no user information, and no `#fragment`;
- it may carry a query of its own, which is preserved, but it may not already
  use the keys `code` or `authentication`, because those are what the answer is
  returned in.

## The exchange

1. Send the person to the AbandonAuth login page with your `application_id` and
   your registered `callback_uri`.
2. They come back to that callback with a `code` query parameter. It is
   one-time, short-lived, and bound to your application.
3. Your **server** spends it at `POST /api/login`, sending the code in the
   `exchange-token` header and identifying your application in the body with its
   `id` and `refresh_token`. You get back a token for that person.
4. Call `GET /api/me` with that token as a `Bearer` credential to identify them.

Spend the code from your server, not from the browser: it identifies your
application with your application's own credential.

Resetting your application's credential invalidates every token issued before
the reset.

# Running AbandonAuth

Every setting is read from the environment. The ones that carry no secret are
also accepted as a command-line flag. All of them are validated at start-up: a
setting that is missing or unusable stops the process with a message naming it.

## Settings

| Setting | Default | Required | What it is |
| --- | --- | --- | --- |
| `DATABASE_URL` | | yes | **environment only.** PostgreSQL connection URL. Scheme must be `postgres` or `postgresql` |
| `JWT_SECRET` | | yes | **environment only.** The root every signing key is derived from. **At least 64 bytes** |
| `JWT_HASHING_ALGO` | `HS512` | yes | must be exactly `HS512` |
| `ABANDON_AUTH_URL` | | yes | this API's own origin, and the issuer of its tokens |
| `ABANDON_AUTH_SITE_URL` | | yes | the site's origin. The only origin allowed to call the API from a browser |
| `ABANDON_AUTH_DEVELOPER_APP_ID` | | yes | the developer application that stands for this service's own site |
| `BIND_ADDRESS` | `0.0.0.0:8000` | no | `host:port` to listen on |
| `TRUSTED_PROXY_CIDRS` | `127.0.0.1/32,::1/128` | no | whose forwarding headers are believed. **See below** |
| `ABANDON_AUTH_API_ADDRESS` | `ABANDON_AUTH_URL` | no | where the site's own server dials the API; `http://abandonauth:8000` on the compose network |
| `API_PORT`, `WEBSITE_PORT` | `8000`, `3000` | no | the host ports `compose.yml` publishes the two services on |
| `API_BUILD_TARGET` | `deployment` | no | which of the two API builds `compose.yml` builds |
| `JWT_EXPIRES_IN_SECONDS_SHORT_LIVED` | `120` | no | one-time code lifetime. Capped at 120 seconds |
| `JWT_EXPIRES_IN_SECONDS_LONG_LIVED` | `2592000` | no | browser session lifetime. Capped at 30 days |
| `DEBUG` | `false` | no | development build only; the published image refuses to start with it set |
| `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `ABANDON_AUTH_DISCORD_CALLBACK` | | yes | see [Discord](./docs/DISCORD-OAUTH2.md) |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `ABANDON_AUTH_GITHUB_CALLBACK` | | yes | see [GitHub](./docs/GITHUB-OAUTH2.md) |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK` | | yes | see [Google](./docs/GOOGLE-OAUTH2.md) |

Each `_CLIENT_SECRET` is environment only, alongside `DATABASE_URL` and
`JWT_SECRET`. All three provider registrations are required.

`ABANDON_AUTH_URL` and `ABANDON_AUTH_SITE_URL` are origins: scheme, host and an
optional port, with no path. Every endpoint is under `/api`, which belongs to
the API and is never part of either setting. Outside a loopback development
build both must be `https`.

## The signing secret

Provision at least 64 random bytes from a secret manager. Replacing it
invalidates every credential this service has issued, so after changing it run:

```shell
abandonauth database rotate-auth-epoch
```

That withdraws every access token, login in progress, one-time code and browser
session. Run it during a maintenance window; everyone signs in again afterwards.

## Behind a reverse proxy

Request budgets are counted per client address. A forwarding header
(`X-Forwarded-For`, `X-Real-IP`) is believed only when the connection came from
an address inside `TRUSTED_PROXY_CIDRS`; from anywhere else it is ignored.

The default, `127.0.0.1/32,::1/128`, covers no proxy and a sidecar on the
loopback interface. For any other proxy (another container, an ingress, a load
balancer) set it to the ranges that proxy connects from:

```dotenv
TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12
```

Leaving the default in that situation collapses every request onto the proxy's
address, so one busy client exhausts a budget shared by everybody. Trusting too
much is worse: `0.0.0.0/0` lets any client choose the address it is counted as,
which disables rate limiting. List only the ranges your proxy connects from, and
make sure that proxy sets the header itself rather than passing through
whatever it received.

## The published image

The image built from `src/api/Dockerfile` (the `deployment` target) contains no
password sign-in, refuses to start with `DEBUG` set, runs as an account that is
not root, and holds nothing but the binary and a certificate bundle. Migrations
are embedded in the binary. The API documentation is served at `/api/docs` and
the schema at `/api/openapi.json`.

`compose.yml` builds that target unless `API_BUILD_TARGET` names the other one.
Deploy with:

```shell
docker compose up --build -d
```

It reads `.env` from the repository root. The database publishes no host port
and is on a network the site does not join.

The same image started with `abandonauth maintenance` answers every request
with a 503 and `Retry-After`. It opens no database connection and reads no
setting but the address, so it starts when the configuration itself is the
problem.

## The database

`abandonauth serve` applies outstanding migrations before it accepts a request.
It migrates only an empty database or one it migrated itself; anything else is
refused and left as it was found, so start a deployment against an empty
database and do not delete a volume to get past a refusal.

To recover from a backup: serve `abandonauth maintenance`, restore a backup of
a database this service migrated, start the deployment image again, and run
`abandonauth database rotate-auth-epoch` if the signing secret changed.

# Local Development

## Prerequisites

| Needed for | Install |
| --- | --- |
| Everything | [Docker](https://docs.docker.com/get-docker/) |
| The API checks on your own machine | [Go](https://go.dev/dl/) 1.27 |
| The site's tests and build | [Node](https://nodejs.org/) 24 |
| The commit hooks | [pre-commit](https://pre-commit.com/#install) |

## First time install

Create your `.env` in the root of the project; copy `.env.sample` as the base.
Fill in the provider registrations:

- [Discord](./docs/DISCORD-OAUTH2.md)
- [GitHub](./docs/GITHUB-OAUTH2.md)
- [Google](./docs/GOOGLE-OAUTH2.md)

Then:

```shell
docker compose up --build
```

`API_BUILD_TARGET=development` in the sample selects the API build carrying
password sign-in, which also needs `DEBUG=true`.

The site is on `WEBSITE_PORT` and the API on `API_PORT`, 3000 and 8000 in the
sample. Sign in through the site on port 3000: that is the origin the sign-in
cookies belong to. The API answers directly at <http://localhost:8000/api/me>
and the documentation at <http://localhost:8000/api/docs>.

Password sign-in (`/api/create_test_user`, `/api/login_test_user`) is served
only from a loopback listener, so to use it run the API directly with
`BIND_ADDRESS=127.0.0.1:8000` rather than through compose.

## Checks

```shell
./scripts/check.sh                # codegen, formatting, lint, build, unit tests
./scripts/check.sh --quick        # the same, skipping codegen and go mod tidy
./scripts/check.sh --fix-fmt      # format the source, then check
./scripts/check.sh --integration  # also the race, database and coverage checks; needs Docker
./scripts/db.sh down              # remove the test database when you are done

npm --prefix src/website test
npm --prefix src/website run build
```

On Windows run them through Git Bash rather than invoking the `.sh` file from
PowerShell:

```powershell
& "C:\Program Files\Git\bin\bash.exe" scripts/check.sh
```

CI runs the same script. `--integration` holds every package to 80% statement
coverage. The sqlc and Swagger output is generated on every run, is not
committed, and is never edited by hand.

## Migrations

The schema is the [goose](https://github.com/pressly/goose) migrations under
[`src/api/internal/database/migrations/`](./src/api/internal/database/migrations),
embedded in the binary and applied by `abandonauth serve` on start-up. goose is
a pinned tool in `src/api/go.mod`, so it needs no separate install.

To add one, from `src/api`:

```shell
go tool goose -dir internal/database/migrations create <what_it_does> sql
```

Queries live in
[`src/api/internal/database/queries/`](./src/api/internal/database/queries);
sqlc regenerates the Go for them on the next `./scripts/check.sh`.

## Pre-commit

Install the hooks so you never fail linting in CI:

```shell
pre-commit install
```
