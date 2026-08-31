# Auth(entication)

Authentic Auth Service... Provides identification of a user from multiple external services.

Currently supported:
- Discord
- GitHub
- Google

# Using AbandonAuth

## Using AbandonAuth to Secure Your Application

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

For a quick example of how a browser is signed in, see the site's login page,
[`src/website/app/pages/login.vue`](./src/website/app/pages/login.vue).

# Local Development Guide

## Prerequisites

| Needed for | Install |
| --- | --- |
| Everything | [Docker](https://docs.docker.com/get-docker/) |
| The API checks on your own machine | [Go](https://go.dev/dl/) 1.21 or newer |
| The site's tests and build | [Node](https://nodejs.org/) 24 |
| The commit hooks | [pre-commit](https://pre-commit.com/#install) |

`src/api/go.mod` asks for Go 1.27, and `GOTOOLCHAIN` defaults to `auto`, so a
newer toolchain is fetched for you if the one you have is older. Nothing here
needs a C compiler: the checks that do, the race detector among them, run inside
a container.

## First time install

Create your `.env` in the root of the project; copy `.env.sample` as the base.
It carries every setting the API reads, with placeholders. Fill in the provider
registrations you want:

- [Discord](./docs/DISCORD-OAUTH2.md)
- [GitHub](./docs/GITHUB-OAUTH2.md)

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

The sqlc and Swagger output is generated on every run and is not committed.
Never edit it.

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

A database that already holds the tables without a record of this service having
migrated them is taken over once, deliberately, with
`abandonauth database adopt-existing-schema`. Run it with `--verify-only` first:
it reports what it would do and changes nothing.

## Pre-commit

Install the hooks so you never fail linting in CI:

```shell
pre-commit install
```
