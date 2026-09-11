# Architecture

How the service is put together and how a sign-in travels through it. Paths are
in `.claude/docs/repo-map.md`; the rules a change must obey, and the normative
wording of every control named here, are in `.claude/docs/security.md` → "The
controls in force, and where they live".

## Runtime

- `compose.yml` runs the Go API, the Nuxt site and PostgreSQL, for development
  and production alike; only `.env` differs, and its `API_BUILD_TARGET` picks
  the `development` build over the published `deployment` one.
- API and site publish `API_PORT` and `WEBSITE_PORT`. The database publishes
  nothing: an internal network the site does not join, reachable at
  `database:5432` from the API alone, denied outbound access. The API is on both
  networks and so still reaches the provider APIs.
- No web framework: a `net/http` router, interface-backed services, sqlc queries
  over pgx.
- Only routes `internal/web/routes.go` declares are answered, and `serve`
  refuses to start while `MissingHandlers()` is non-empty.
- `/api` is the route root and part of the contract: browser, site and service
  all name `/api/me`, and no component of a deployment adds or removes the root.
- One spelling per route: `internal/web/requesttarget.go` refuses a raw target
  carrying an escape, a repeated slash, a backslash or a dot segment, before the
  router can decode or clean it into an address that spends a login, a code or a
  session.
- `internal/web/server.go` composes every service from the configuration and the
  pool and fixes the middleware order and connection deadlines;
  `internal/config` validates once at start-up and is immutable afterwards.

| Layer | Holds |
| --- | --- |
| `internal/web/` | HTTP translation: read the request, call a service, shape the answer |
| `internal/services/` | the behaviour itself, behind small interfaces with typed sentinel errors |
| `internal/database/query/` | sqlc output over pgx; handlers never reach it |

## Identity flows

`ABANDON_AUTH_DEVELOPER_APP_ID` names a developer application standing for this
service's own site: an ordinary registered application, and what decides how a
login ends. Its registered callback is the site's origin, where the session
cookie belongs, plus `/api/ui`, the address the site forwards to.

The site builds no provider address. `GET /api/ui/{provider}/authorize`, given
an application and a callback:

1. checks the callback is one that application registered, exactly;
2. creates opaque state, a browser-binding value, a PKCE verifier and, for
   Google, a nonce;
3. stores their digests, the application, the exact callback and the encrypted
   verifier in a row expiring in five minutes;
4. sets the short-lived binding cookie and redirects to the provider's own fixed
   HTTPS address.

Only the opaque state travels in that redirect, useless without the browser's
cookie.

The callback consumes state in one `DELETE ... RETURNING` that also requires the
browser binding, the provider and the current auth epoch: state works once, for
one browser, on whichever worker sees it. The provider's authorization code is
then exchanged with the verifier and the identity resolved to a user, one
created atomically the first time that provider identifier is seen; identities
are never linked by username or email. Google's identity token is verified in
full: issuer, audience and `azp`, RS256 only, signature against the published
keys, nonce, `at_hash`, clock claims within thirty seconds.

| The login was for | The browser gets |
| --- | --- |
| the site's own application | a browser session, created directly, and a redirect to the registered callback |
| any other application | a one-time code in the redirect, spent server-side by that application at `POST /api/login` |

The site never receives a code, so no internal credential sits in a browser. An
external application's code is opaque, short-lived, bound to that application,
stored only as a digest, spent by a delete a second attempt cannot repeat.

Either way the browser goes to the callback exactly as registered: checks run
against a copy whose scheme and host are lower cased, the redirect is built from
the registered string, only the one response parameter is appended. Declining at
the provider returns the browser to that same validated string, nothing added.

## Browser authority

One origin may use this API from a browser, and only at an address the route
table names: `internal/web/cors.go` emits no permission header and answers no
preflight otherwise, so an unserved target is reported unserved rather than
described.

A signed-in browser holds a random value; the database holds its digest, the
user it stands for, and a second value the site must echo back. Expiry is
absolute — use does not extend it — and ending a session is a delete, effective
immediately for every worker.

| Cookie | Read by script | Carries |
| --- | --- | --- |
| session | no | the value a session is looked up by |
| CSRF | yes | the value the site copies into `X-CSRF-Token` |
| login binding | no | the value tying a login in progress to this browser |

`RequireSecureCookies()` chooses between `__Host-`-prefixed `Secure` cookies and
host-only loopback equivalents. A cookie-authenticated request that changes
something must also carry an exact `Origin` and a CSRF token matching the digest
stored with the session.

## Tokens, budgets, and expiry

- Two access token classes, never interchangeable: one for a person, one for a
  developer application. `internal/services/keyring` derives their signing keys
  separately from the signing root, and each token is validated against its own
  claims.
- A developer application's token carries the credential version it was issued
  under, so resetting that credential refuses every token issued before.
- Every check is measured against the auth epoch, which
  `database rotate-auth-epoch` replaces in one transaction, withdrawing every
  token, login in progress, one-time code and session at once.
- `internal/services/ratelimit` counts fixed windows in the database, keyed by a
  digest of whoever is limited rather than a client address in clear, so budgets
  hold across workers. Anyone can name a public application identifier, so a
  caller counts against its address until something unguessable is proven.
  Budgets are constants in the binary.
- Forwarding headers are believed only from a peer inside
  `TRUSTED_PROXY_CIDRS`; the deployment section of `README.md` tells an operator
  what to set it to.
- `internal/services/housekeeping` sweeps expired logins, codes, sessions,
  withdrawn tokens and budget windows on a ticker `serve` starts and stops with
  its own context. Sweeps are bounded and remove nothing still usable: granting
  anything from such a row already requires it unexpired.
- Database time is authoritative for every expiry, so a wrong clock on an API
  host cannot extend a credential.

## Persistence

The schema is the goose migrations under `internal/database/migrations/`,
embedded in the binary, so a deployment carries no schema file. The SQL under
`internal/database/queries/` becomes the generated, gitignored `query` package.

`serve` migrates before answering a request, and decides whether it may under
the same advisory lock it migrates under, so one instance never judges a
database another is halfway through building. It migrates an empty database, one
the baseline built, and one already at a version the binary carries. Every other
state is refused with the database left exactly as found: account tables lacking
either the migration history or the `schema_identity` marker the baseline
writes, a partial set of them, a gap or unknown version in the history, a
migration recorded unfinished. That marker stops a hand-written history passing
a schema off as one these migrations built.

## Build modes

One Dockerfile, two runtime targets; a build naming none produces the last
stage. The published `deployment` target has no password sign-in — those
handlers compile only under `-tags=devtools` — and refuses to start with `DEBUG`
set at all. `development` carries them, served only with debug mode on and a
loopback-only bind.

Both carry the documentation and the schema, which this public API serves
whatever the build and configuration. Swag's annotations carry no build
constraints, so its document names password sign-in in either build;
`internal/web/apidocumentation.go` narrows it to the addresses the running build
serves before publishing. The document declares no server and every path is a
whole `/api` address, so a reader combines it with the origin it came from; the
page reads the schema through a relative reference for the same reason.

## The site boundary

The site holds no access token: it sends the session cookie the API set, copies
the readable CSRF cookie into `X-CSRF-Token` on writes, and builds no provider
address. Its Nitro route proxies `/api/**` and hands redirects back to the
browser rather than following them, because a provider callback's redirect also
carries the session cookie.

The path travels unchanged: the browser asks the site for `/api/me` and the API
is asked for `/api/me`. The development forwarder is mounted on `/api` and hands
on the path with that root removed, so pointing it at the API address plus the
root arrives at the same place. The site dials `ABANDON_AUTH_API_ADDRESS`, which
the container can be started with, not `ABANDON_AUTH_URL`, the origin a browser
and a registered callback URI use, which does not resolve inside the stack. Both
are origins; neither carries `/api`.
