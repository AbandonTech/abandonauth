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
  `database:5432` from the API and the `migrations` and `provisioning` services
  alone, denied outbound access. The API is on both networks and so still
  reaches the provider APIs; `migrations` and `provisioning` are on the internal
  one only.
- Start-up order is the migration and provisioning boundary: PostgreSQL
  healthy, then the one-shot `migrations` service runs `goose up`, then the
  one-shot `provisioning` service runs `abandonauth provision`, then the API
  starts only once both exit successfully, then the site. See "Persistence".
- No web framework: a `net/http` router, interface-backed services, sqlc queries
  over pgx.
- Only routes `internal/web/routes.go` declares are answered, and `serve`
  refuses to start while `MissingHandlers()` is non-empty.
- `/api` is the route root and part of the contract: browser, site and service
  all name `/api/me`, and no component of a deployment adds or removes the root.
- One spelling per route: `internal/web/requesttarget.go` refuses a raw target
  carrying an escape, a repeated slash, a backslash or a dot segment, before the
  router can decode or clean it into an address that spends a login, a code or a
  session. Whether an address is one the route table declares, which CORS and
  the 404/405 answers both need, is asked of a `net/http` router built from the
  route table with the methods left off, so there is no second matcher to
  drift from the one that serves.
- `internal/web/server.go` composes every service from the configuration and the
  pool and fixes the middleware order and connection deadlines;
  `internal/config` validates once at start-up and is immutable afterwards.
- `cmd/operations.go` opens the listener before it starts anything else, so a
  bind failure is reported at once; the housekeeping sweeps run under a context
  that starts once the listener is open and is cancelled however serving ends.
- The outermost middleware records whether a response has been committed, by a
  write, a flush or a hijack, and a handler that fails after that point is not
  answered a second time. The recovered value is never logged.

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

`abandonauth provision` creates it (`internal/services/siteapplication`) when
no application holds the configured identifier: an owner named `abandonauth`
with no provider or password account, so no sign-in reaches it; the application
named `AbandonAuth`, whose generated credential is stored as a hash and
discarded; and the callback, derived from `ABANDON_AUTH_SITE_URL` with one
trailing slash dropped and `web.SiteEntryPath` appended, the spelling the site's
`siteCallbackUri` builds from the same setting. The three are one transaction.
The identifier alone decides: an application already holding it is left exactly
as it is, whoever owns it.

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
the registered string, only the one response parameter is appended, under the
key `internal/urlpolicy` owns (`code`, or `authentication` for Google) and
refuses at registration. Declining at the provider returns the browser to that
same validated string, nothing added.

An application's callback set is replaced under the application's row lock, so
two replacements arriving together run one after the other and leave one
submitted set; a replacement that finds the application gone is answered as
not found.

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
  separately from the signing root. Each class has one shape, held in
  `internal/services/tokens`: its key and key identifier, the scope string it
  carries for a given audience, whether its audience must be the site, and
  whether it carries a credential version. A token is accepted only when every
  claim is exactly that shape, with canonical non-nil identifiers and a validity
  interval of exactly the access lifetime from the moment of issue.
- A developer application's token carries the credential version it was issued
  under, so resetting that credential refuses every token issued before.
- Every check is measured against the auth epoch, which
  `database rotate-auth-epoch` replaces in one transaction holding its row lock,
  withdrawing every token, login in progress, one-time code and session at once.
- `internal/services/ratelimit` counts fixed windows in the database, keyed by a
  digest of whoever is limited rather than a client address in clear, so budgets
  hold across workers. The window a request falls in, and how long a refused
  caller is told to wait, are decided by the database clock, so instances with
  different clocks count one client in one window. Anyone can name a public
  application identifier, so a caller counts against its address until
  something unguessable is proven. Budgets are constants in the binary.
- Forwarding headers are believed only from a peer inside
  `TRUSTED_PROXY_CIDRS`, and `X-Forwarded-For` is read from its trusted end
  across every header line: trusted hops are skipped and the nearest untrusted
  address is the client, so nothing a client prepended is counted. A chain that
  cannot be read in full falls back to the peer. The deployment section of
  `README.md` tells an operator what to set the ranges to.
- Every transaction is abandoned through `internal/database/rollback.go`, which
  detaches from the request's cancellation and bounds the cleanup, so a client
  that gives up cannot leave a connection or a row lock held.
- `internal/services/housekeeping` sweeps expired logins, codes, sessions,
  withdrawn tokens and budget windows on a ticker `serve` starts once its
  listener is open and stops however serving ends. Sweeps are bounded and
  remove nothing still usable: granting anything from such a row already
  requires it unexpired.
- Database time is authoritative for every expiry, so a wrong clock on an API
  host cannot extend a credential.

## Persistence

The schema is the Goose SQL migrations under `src/api/migrations/`. The SQL
under `internal/database/queries/` becomes the generated, gitignored `query`
package, which sqlc builds against those migrations.

The application has no knowledge of migrations: it imports no migration library,
reads no migration file or history, and never changes the schema. Both image
targets carry a PostgreSQL-only build of the pinned Goose CLI and the migration
files beside the service binary, and `compose.yml` runs them as the `migrations`
service: the same image with Goose as its entrypoint, `-env=none`, four settings
(`GOOSE_DRIVER`, `GOOSE_MIGRATION_DIR`, a password-free `GOOSE_DBSTRING`,
`PGPASSWORD`), and the internal database network alone. The API depends on it
completing successfully, so a failed migration leaves the API created and never
started. A changed API container is replaced before the migration runs; an
unchanged running one keeps serving, which is how `docker compose up migrations`
followed by `docker compose up` migrates without stopping it.

Goose takes no database-wide lock, so the one `migrations` service of a Compose
project is the only migration controller its project-scoped database has. Every
Up migration must work with both the build serving and the one being deployed.
Down migrations run only when an operator runs a Goose command through that
service; nothing starts one.

An API started against a database no one migrated answers nothing that needs
the database: each such request fails closed.

The site's application is data, not schema, so no migration carries it.
`compose.yml` runs `abandonauth provision` as the `provisioning` service, the
same image with the service binary as its entrypoint, receiving `DATABASE_URL`
and `DEBUG` alone, on the internal database network alone. It depends on the
migration completing, and the API depends on it completing, so a refused input
or a database failure leaves the API created and never started. Provisioning
checks the site origin with `config.ParseSiteOrigin`, the parser `serve` uses,
so both apply one transport rule for a build and debug setting. The ordinary
test template is migrated and never provisioned.

Rotating the authority and any migration changing authority-bound state both
begin by locking the `auth_epoch` row `FOR UPDATE`, so neither interleaves with
the other or with a second rotation.

## Build modes

One Dockerfile, two runtime targets; a build naming none produces the last
stage. The published `deployment` target has no password sign-in — those
handlers compile only under `-tags=devtools` — and refuses to start with `DEBUG`
set at all. `development` carries them, served only with debug mode on and a
loopback-only bind.

Both carry the documentation and its OpenAPI schema, which this public API
serves whatever the build and configuration, the Goose CLI and migration files
the `migrations` service runs, and the `provision` command the `provisioning`
service runs. Swag's annotations carry no build
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
