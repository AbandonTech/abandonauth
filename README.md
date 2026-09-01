# Auth(entication)

Authentic Auth Service... Provides identification of a user from multiple external services.

Currently supported:
- Discord
- GitHub
- Google

This README has three parts, for three different jobs:

- [Integrating your application](#integrating-your-application) — you have an
  application and you want people to sign in to it with AbandonAuth.
- [Running AbandonAuth](#running-abandonauth) — you are deploying this service
  and need to know what it expects of its environment.
- [Local development](#local-development) — you are changing this repository.

# Integrating your application

You do not configure anything in this service's environment. You register a
developer application, and your own server speaks the exchange below.

## Register a developer application

1. Login to [AbandonAuth](https://auth.abandontech.cloud)
2. Create a Developer Application
   1. Navigate to `Developer Applications`
   2. Click `Create a new application`, then click `Create Application`
   3. Take note of/save your application token as it will never be visible again (you can reset it anytime)
3. Navigate back to `Developer Applications` and click on the recently created app's UUID to edit it then click `Edit Callback URIs`. The callback URI you specify is where AbandonAuth will redirect users after authenticating. It should be whichever address your server is using to finish handling the login process.  Some examples are as follows:
   1. For local dev you could have something like this `"http://your_computers_local_ip:8001/login/abandonauth-callback"`
      1. Or you should be able to use localhost `"http://localhost:8001/login/abandonauth-callback"`
   2. For a production website, you may use a domain name to redirect to `https://mc.abandonauth.cloud/api/callback`
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
2. They come back to that callback with a `code` query parameter. It is opaque,
   one-time, short-lived, and bound to your application: nobody else can spend
   it, and it works once.
3. Your **server** spends it at `POST /login`, sending the code in the
   `exchange-token` header and identifying your application in the body with its
   `id` and `refresh_token`. You get back a token for that person.
4. Call `GET /me` with that token as a `Bearer` credential to identify them.

Spend the code from your server, not from the browser: it identifies your
application with your application's own credential.

If you reset your application's credential, every token issued before the reset
stops working immediately. That is what makes a reset useful.

# Running AbandonAuth

Every setting is read from the environment, and also accepted as a command-line
flag. They are validated once at start-up: a setting that is missing or
unusable stops the process with a message naming it, and never repeating its
value.

## Settings

| Setting | Default | Required | What it is |
| --- | --- | --- | --- |
| `DATABASE_URL` | | yes | PostgreSQL connection URL. Scheme must be `postgres` or `postgresql` |
| `JWT_SECRET` | | yes | the root every signing key is derived from. **At least 64 bytes** |
| `JWT_HASHING_ALGO` | `HS512` | yes | must be exactly `HS512`; anything else fails closed rather than selecting an algorithm |
| `ABANDON_AUTH_URL` | | yes | this API's own origin, and the issuer of its tokens |
| `ABANDON_AUTH_SITE_URL` | | yes | the site's origin. The only origin allowed to call the API from a browser |
| `ABANDON_AUTH_DEVELOPER_APP_ID` | | yes | the developer application that stands for this service's own site |
| `BIND_ADDRESS` | `0.0.0.0:8000` | no | `host:port` to listen on |
| `TRUSTED_PROXY_CIDRS` | `127.0.0.1/32,::1/128` | no | whose forwarding headers are believed. **See below** |
| `JWT_EXPIRES_IN_SECONDS_SHORT_LIVED` | `120` | no | one-time code lifetime. Capped at 120 seconds |
| `JWT_EXPIRES_IN_SECONDS_LONG_LIVED` | `2592000` | no | browser session lifetime. Capped at 30 days |
| `DEBUG` | `false` | no | development build only; the published image refuses to start with it set |
| `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `ABANDON_AUTH_DISCORD_CALLBACK` | | yes | see [Discord](./docs/DISCORD-OAUTH2.md) |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `ABANDON_AUTH_GITHUB_CALLBACK` | | yes | see [GitHub](./docs/GITHUB-OAUTH2.md) |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK` | | yes | see [Google](./docs/GOOGLE-OAUTH2.md) |

All three provider registrations are required. There is no way to run with two
of them.

`ABANDON_AUTH_URL` and `ABANDON_AUTH_SITE_URL` are parsed as origins, not as
general URLs: scheme, host and an optional port only — no path beyond `/`, no
query, no fragment, no user information. Outside a loopback development build
both must be `https`.

`ABANDON_AUTH_DEVELOPER_APP_ID` decides which logins produce a browser session
rather than a one-time code, so it must name this deployment's own site
application and nothing else.

## The signing secret

Provision at least 64 random bytes from a secret manager. Replacing it
invalidates every credential this service has issued, so after changing it run:

```shell
abandonauth database rotate-auth-epoch
```

That withdraws every access token, login in progress, one-time code and browser
session in one transaction. Run it during a maintenance window; everyone signs
in again afterwards.

## Behind a reverse proxy

**This is the one thing the service genuinely requires of its environment.**

Request budgets are counted per client address. A forwarding header
(`X-Forwarded-For`, `X-Real-IP`) is believed **only** when the connection itself
came from an address inside `TRUSTED_PROXY_CIDRS`. Anywhere else it is ignored,
because anyone can send one, and believing it would let a single client present
a new identity per request and never be limited.

The default, `127.0.0.1/32,::1/128`, is right when nothing is in front of the
service, and when the proxy is a sidecar sharing the loopback interface.

If the proxy is **anywhere else** — another container, a Kubernetes ingress, a
load balancer, or a CDN terminating at your origin — set
`TRUSTED_PROXY_CIDRS` to the ranges it connects from:

```dotenv
TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12
```

Leaving the default in that situation is not a security problem but is an
availability one: every request collapses onto the proxy's single address, so
one busy client exhausts a budget shared by everybody.

Trusting too much is the dangerous direction. `0.0.0.0/0` makes the header
client-controlled, which disables rate limiting entirely. List only the ranges
your proxy actually connects from, and make sure that proxy sets
`X-Forwarded-For` itself rather than passing through whatever it received.

Nothing else about the service is proxy-dependent: it needs no particular
provider or vendor, and no other header.

## The published image

The image built from `src/api/Dockerfile` (the `deployment` target) contains
neither password sign-in nor the API documentation, refuses to start with
`DEBUG` set, runs as an account that is not root, and holds nothing but the
binary and a certificate bundle. Migrations travel inside the binary, so no
schema file is deployed alongside it.

`abandonauth serve` applies outstanding migrations before it accepts a request.
A database that already holds the account tables with no record of this service
having migrated them is refused rather than migrated.

The same image started with `abandonauth maintenance` answers every request with
a 503 and `Retry-After`. It opens no database connection and reads no setting
but the address, so it still starts when the reason for a failure is the
configuration itself.

# Local Development

## Prerequisites

| Needed for | Install |
| --- | --- |
| Everything | [Docker](https://docs.docker.com/get-docker/) |
| The API checks on your own machine | [Go](https://go.dev/dl/) |
| The site's tests and build | [Node](https://nodejs.org/) 24 |
| The commit hooks | [pre-commit](https://pre-commit.com/#install) |

`src/api/go.mod` asks for Go 1.27, and `GOTOOLCHAIN` defaults to `auto`, so a
newer toolchain is fetched for you if the one you have is older. Nothing here
needs a C compiler: the checks that do, the race detector among them, run inside
a container.

## First time install

Create your `.env` in the root of the project; copy `.env.sample` as the base.
It carries every setting the API reads, with placeholders. Fill in the provider
registrations:

- [Discord](./docs/DISCORD-OAUTH2.md)
- [GitHub](./docs/GITHUB-OAUTH2.md)
- [Google](./docs/GOOGLE-OAUTH2.md)

Then:

```shell
docker compose up --build
```

The site is on port 3000 and the API on 8000. Reach the API through the site,
at `/api`: that is the origin the sign-in cookies belong to, and a provider that
returns a browser straight to port 8000 sends none of them.

Compose builds the API's `development` image, which is the variant carrying
password sign-in and the API documentation. Both need `DEBUG=true`, which
`.env.sample` sets. The published image is a separate build that contains
neither and refuses to start with `DEBUG` set at all.

The documentation is at <http://localhost:3000/api/docs>.

## Checks

One script, and CI runs the same one, so the two cannot drift.

```shell
./scripts/check.sh                # codegen, formatting, lint, build, unit tests
./scripts/check.sh --quick        # the same, skipping codegen and go mod tidy
./scripts/check.sh --fix-fmt      # format the source, then check
./scripts/check.sh --integration  # also the race, database and coverage checks
./scripts/check.sh --images       # also build both images and check what they hold
./scripts/db.sh down              # remove the test database when you are done

npm --prefix src/website test
npm --prefix src/website run build
```

`--integration` and `--images` need Docker; the rest runs on your machine.
`./scripts/check.sh` reports formatting rather than correcting it, so that a
check never rewrites your work; `--fix-fmt` is how you correct it.

Every package is held to 80% statement coverage by `--integration`. The sqlc and
Swagger output is generated on every run and is not committed. Never edit it.

## Migrations

The schema is `.sql` files under
[`src/api/internal/database/migrations/`](./src/api/internal/database/migrations),
run by [goose](https://github.com/pressly/goose). They are compiled into the
binary, so a deployment needs no schema file alongside it.

`abandonauth serve` applies anything outstanding before it accepts a request, so
`docker compose up` migrates a development database for you.

To add one, write a new file named `<UTC timestamp>_<what it does>.sql` with
`-- +goose Up` and `-- +goose Down` sections. Down is for tests only; a
deployment never runs it. Queries live in
[`src/api/internal/database/queries/`](./src/api/internal/database/queries) and
`sqlc` turns them into Go on the next check.

## Pre-commit

Install the hooks so you never fail linting in CI:

```shell
pre-commit install
```
