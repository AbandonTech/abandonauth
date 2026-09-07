# Architecture

How the service is put together and how a sign-in travels through it. For where
a file lives, read `.claude/docs/repo-map.md`; for the rules a change must obey,
read `.claude/docs/security.md`.

## Runtime

AbandonAuth is a Go API, a Nuxt site, and PostgreSQL. `compose.yml` runs all
three, for development and for production alike; `.env` is the only thing that
differs between them, and `API_BUILD_TARGET` in it is what selects the
`development` build over the published `deployment` one.

The API and the site publish `API_PORT` and `WEBSITE_PORT`. The database
publishes nothing: it is on an internal network the site does not join, so it
is reachable at `database:5432` from the API and from nowhere else, and that
network denies it outbound access. The API is on both networks, which is how it
still reaches the provider APIs.

The API is a `net/http` router in front of interface-backed services in front of
sqlc queries over pgx. There is no web framework. Requests are answered only for
the routes `internal/web/routes.go` declares, and `serve` refuses to start while
`MissingHandlers()` is non-empty, so a declared route can never answer with a
surprise instead of its contract.

Every one of those routes is under `/api`, which is the API's own route root and
part of its contract: `/api/me` is what a browser asks for, what the site
forwards, and what the service answers, so no component of a deployment adds or
removes it. Each route is also spelled one way. `internal/web/requesttarget.go`
refuses a request target whose raw path carries an escape, a repeated slash, a
backslash or a dot segment before the router can decode or clean it into an
address that spends a login, a code or a session.

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

Its registered callback is the site's origin plus `/api/ui`. It is the site's
origin because that is where the session cookie belongs, and `/api/ui` because
that is the address the site forwards to this service's entry point.

## Identity flows

### Starting a login

The site builds no provider address. A browser goes to
`GET /api/ui/{provider}/authorize` with an application and a callback, and the
API:

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
| any other application | a one-time code in the redirect, which that application spends server-side at `POST /api/login` |

The site never receives a code, so there is no internal credential in a browser
to steal. An external application's code is opaque, short-lived, bound to that
application, stored only as a digest, and spent by a delete that a second
attempt cannot repeat.

Either way the browser goes to the callback exactly as it was registered. The
policy checks run against a copy whose scheme and host are lower cased, but the
redirect is built from the registered string, and only the one response parameter
is appended to it. A person who declines at the provider is returned to that same
validated string with nothing added.

## Browser authority

Exactly one origin may use this API from a browser, and only for an address the
route table names: `internal/web/cors.go` emits no permission header and answers
no preflight for anything else, so a target that is not served is reported as
not served rather than described.

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

`serve` migrates before it answers a request, and decides whether it may under
the same advisory lock it migrates under, so one instance never judges a database
another is halfway through building. It migrates an empty database, one the
baseline built, and one already at a version the binary carries. Everything else
— account tables without both the migration history and the `schema_identity`
marker the baseline writes, a partial set of them, a gap or an unknown version in
the history, a migration recorded as unfinished — is refused with the database
left exactly as it was found. The marker is what stops a hand-written history
from passing a schema off as one these migrations built.

Database time is authoritative for every expiry, so a wrong clock on an API host
cannot extend a credential.

## Build modes

One Dockerfile, two runtime targets, and it is the last stage that a build naming
no target produces. The published `deployment` target contains no password
sign-in, because those handlers live in files compiled only under
`-tags=devtools`, and it refuses to start with `DEBUG` set at all. The
`development` target carries them, and serves them only with debug mode on and a
loopback-only bind.

The documentation and the schema are in both. This is a public API, so they are
served whatever the build and whatever the configuration. The annotations swag
reads carry no build constraints, so the document it produces names password
sign-in in either build; `internal/web/apidocumentation.go` narrows it to the
addresses the running build actually serves before publishing it.

The document declares no server and every path in it is a whole `/api` address,
so a reader combines it with the origin the document came from. The page reads
the schema through a relative reference for the same reason.

## The site boundary

The site holds no access token. It sends the session cookie the API set, copies
the readable CSRF cookie into `X-CSRF-Token` on writes, and builds no provider
address of its own. Its Nitro route proxies `/api/**` to the API and hands
redirects back to the browser rather than following them, because a provider
callback's redirect is also what carries the session cookie.

The path travels unchanged: a browser asks the site for `/api/me` and the API is
asked for `/api/me`. The development forwarder is mounted on `/api` and hands on
the path with that root already removed, so it is pointed at the API address
plus the root and arrives at the same place. The site dials
`ABANDON_AUTH_API_ADDRESS`, which the container can be started with, rather than
`ABANDON_AUTH_URL`, which is the origin a browser and a registered callback URI
use and does not resolve from inside the stack. Both are origins; neither
carries `/api`.
