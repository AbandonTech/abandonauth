# Architecture

How the service is put together and how a sign-in travels through it. For where
a file lives, read `.claude/docs/repo-map.md`; for the rules a change must obey,
read `.claude/docs/security.md`.

## Runtime

AbandonAuth is a Go API, a Nuxt site, and PostgreSQL. `compose.yml` runs all
three for local development and builds the API's `development` target.

The API is a `net/http` router in front of interface-backed services in front of
sqlc queries over pgx. There is no web framework. Requests are answered only for
the routes `internal/web/routes.go` declares, and `serve` refuses to start while
`MissingHandlers()` is non-empty, so a declared route can never answer with a
surprise instead of its contract.

| Layer | Holds |
| --- | --- |
| `internal/web/` | HTTP translation only: read the request, call a service, shape the answer |
| `internal/services/` | what the service actually does, behind small interfaces with typed sentinel errors |
| `internal/database/query/` | sqlc output over pgx; handlers never reach it directly |

`internal/web/server.go` is the composition root: it builds every service from
the configuration and the pool, fixes the middleware order, and sets the
connection deadlines. Configuration is validated once at start-up by
`internal/config` and is immutable afterwards, so a setting cannot be wrong only
sometimes.

## What the site is

`ABANDON_AUTH_DEVELOPER_APP_ID` names a developer application that stands for
this service's own site. It is an ordinary registered application in the schema,
and it is what makes the difference described under "Two ways a login ends".

## Identity flows

### Starting a login

The site builds no provider address. A browser goes to
`GET /ui/{provider}/authorize` with an application and a callback, and the API:

1. checks the callback is one that application registered, exactly;
2. creates opaque state, a browser-binding value, a PKCE verifier and, for
   Google, a nonce;
3. stores the digests of those, the application, the exact callback and the
   encrypted verifier as a row that expires in five minutes;
4. sets the short-lived binding cookie and redirects to the provider's own fixed
   HTTPS address.

Nothing about the login travels in the redirect except the opaque state. A state
value observed in a log or a referrer is useless without the browser's cookie.

### Returning from one

The callback consumes the state in a single `DELETE ... RETURNING` that also
requires the browser binding, the provider and the current auth epoch to match,
so a state value works once, for one browser, whichever worker sees it. Then the
provider's authorization code is exchanged with the verifier, and the identity
is resolved to a user, creating one atomically the first time that provider
identifier is seen. Identities are never linked by username or email.

Google additionally verifies a full OIDC identity token: the issuer, the
audience and `azp`, RS256 only, the signature against the published keys, the
nonce, `at_hash`, and the clock claims within thirty seconds.

### Two ways a login ends

| The login was for | The browser gets |
| --- | --- |
| the site's own application | a browser session, created directly, and a redirect to the registered callback |
| any other application | a one-time code in the redirect, which that application spends server-side at `POST /login` |

The site never receives a code, so there is no internal credential in a browser
to steal. An external application's code is opaque, short-lived, bound to that
application, stored only as a digest, and spent by a delete that a second
attempt cannot repeat.

## Browser authority

A signed-in browser holds a random value; the database holds its digest, the
user it stands for, and a second value the site must echo back. Expiry is
absolute — using a session does not extend it — and ending one is a delete, so
it takes effect immediately for every worker.

| Cookie | Read by script | Carries |
| --- | --- | --- |
| session | no | the value a session is looked up by |
| CSRF | yes | the value the site copies into `X-CSRF-Token` |
| login binding | no | the value that ties a login in progress to this browser |

`RequireSecureCookies()` decides between `__Host-`-prefixed `Secure` cookies and
their host-only loopback equivalents. A request that changes something and
authenticates with cookies must also carry an exact `Origin` and a CSRF token
that matches the digest stored with the session.

## Tokens

Two access token classes exist and are never interchangeable: one for a person,
one for a developer application. Their signing keys are derived separately from
the signing root by `internal/services/keyring` under fixed key identifiers, and
each is validated against its own issuer, audience, subject, scope, type and
lifetime. A developer application's token also carries the credential version it
was issued under, so resetting an application's credential refuses every token
issued before the reset.

Every check is measured against the auth epoch. `database rotate-auth-epoch`
replaces it in one transaction and, with it, withdraws every token, login in
progress, one-time code and session at once.

## Abuse controls

`internal/services/ratelimit` counts requests in fixed windows in the database,
so a budget holds across workers. What is counted is a keyed digest of whoever
is being limited, never a client address in clear. Who is counted matters:
anyone can name a public application identifier, so a caller counts against its
address until something unguessable has been proven. Budgets are constants in
the binary; there is deliberately no setting that raises or removes one.

Forwarding headers are believed only from a peer inside `TRUSTED_PROXY_CIDRS`.
See the deployment section of `README.md`, which is where an operator is told
what that has to be set to.

## Records that expire

`internal/services/housekeeping` sweeps expired logins, one-time codes,
sessions, withdrawn tokens and rate-limit windows on a ticker that `serve`
starts and stops with its own context. The sweeps are bounded and remove nothing
that is still usable: every statement that reads one of those rows to grant
something already requires it to be unexpired.

## Persistence

The schema is the goose migrations under `internal/database/migrations/`,
embedded in the binary, so a deployment carries no schema file. Queries are the
SQL under `internal/database/queries/`; sqlc turns them into the `query` package,
which is generated, gitignored and never edited.

`serve` migrates before it answers a request. A database that already holds the
account tables with no record of this service having migrated them is refused
outright rather than migrated blindly.

Database time is authoritative for every expiry, so a wrong clock on an API host
cannot extend a credential.

## Build modes

One Dockerfile, two runtime targets. The published `deployment` target contains
neither password sign-in nor the documentation UI, because those live in files
compiled only under `-tags=devtools`, and it refuses to start with `DEBUG` set at
all. The `development` target carries both, and serves them only when debug mode
is on; password sign-in additionally requires a loopback-only bind.

## The site boundary

The site holds no access token. It sends the session cookie the API set, copies
the readable CSRF cookie into `X-CSRF-Token` on writes, and builds no provider
address of its own. Its Nitro route proxies `/api/**` to the API and hands
redirects back to the browser rather than following them, because a provider
callback's redirect is also what carries the session cookie.
