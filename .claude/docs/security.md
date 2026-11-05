# Security

Work touching the subjects listed under "Security classification" in
`.agents/abandonauth-agent-workflow.md` requires a sensitive plan and a review
by `abandonauth-security-reviewer` before implementation.

## Secrets

- Read no real `.env` file or local credential. Read `.env.sample` only.
- Never expose a password, client secret, authorization code, JWT, provider
  access or refresh token, session cookie, or private key in output, logs, URLs,
  exceptions, plans, tests, fixtures, snapshots, or commits.
- Hold secrets in `config.Secret`; call `Reveal()` only at the narrow outbound
  call or cryptographic boundary that needs the value.
- `DATABASE_URL`, `JWT_SECRET` and the three provider client secrets are read
  from the environment only. Give none of them a command-line flag: an argument
  is readable by every process on the machine. Steam's sign-in has no secret
  and no Web API key; never add one to reach it.
- Goose gets the database password only as `PGPASSWORD`. `GOOSE_DBSTRING` holds
  none, because Goose quotes it when a connection fails.
- Redact authorization headers, cookies, query strings, and provider response
  bodies from logging and telemetry.

Permission denials here are defense in depth, not a sandbox: Claude Code's
native Windows Bash reaches files through subprocesses despite `Read` denials.
Where secret isolation must hold, work from a secret-free checkout or from WSL2
with Claude's sandbox on, and keep production credentials out of any
agent-accessible worktree.

## OAuth and OIDC

- State is unpredictable, single-use, bound to the initiating browser, expiring,
  and compared in constant time where applicable. It is not a container for
  trusted comma-delimited input.
- PKCE is required for public clients; a confidential-client flow that omits it
  records why. Validate nonce on OIDC responses.
- A public client holds no secret and is never given one. Its redirect is a
  loopback template whose only accepted variation is the port, and nothing is
  redirected to before the client and redirect are both proven.
- Match registered redirect URIs exactly. Define the HTTPS requirement and any
  narrow loopback exception. Never normalize, prefix-match, or accept a
  caller-controlled redirect.
- No access, refresh, exchange, or session token in a redirect query string.
  Authorization codes are short-lived, one-time, audience-bound, and consumed
  atomically in a shared expiring store.
- Validate provider issuer, client/audience, signature, algorithm, nonce, and
  required claims. A user-info response is not proof where the protocol requires
  ID-token validation.
- Account linking requires recent authentication and proof the external identity
  belongs to the current user. Never link on a mutable or unverified attribute.

## Tokens and sessions

- Allowlist signing algorithms; never take an accepted algorithm from token
  input.
- Validate issuer, audience, subject, expiration, not-before, issued-at, token
  type, and required claims, with exact scope and set membership.
- Keep signing keys, audiences, claims, dependencies, and storage separate for
  user, developer application, exchange, access, refresh, and session
  credentials.
- Access credentials are short-lived. Rotation, revocation, key IDs, JWKS,
  replay detection, and refresh-token reuse are explicit design decisions.
- Consume one-time credentials atomically, and correctly across workers:
  in-memory process state is not a distributed replay defense.
- Browser authentication uses `HttpOnly`, `Secure` and appropriate `SameSite`
  cookies; cookie-authenticated state changes need CSRF defense; logout and
  credential reset invalidate server-side authority.

## Authorization and abuse controls

- Deny by default and authorize every protected resource.
- Compare identifiers, scopes, roles, and ownership exactly. Never settle a
  permission with a substring check.
- Prevent identifier probing through consistent authorization and not-found
  behaviour where appropriate.
- Rate-limit only by an authenticated principal, never by an identifier a
  caller merely names, and without enabling account enumeration.
- Debug authentication routes, wildcard CORS, and verbose errors stay
  unreachable in production even when configuration is mistaken.

## The controls in force, and where they live

These are decisions, not incidental behaviour. Weakening one is a security
change: it needs a sensitive plan, a review, and abuse-case tests, whatever else
the work was about.

| Control | Where |
| --- | --- |
| Exactly `HS512`, checked rather than obeyed; per-purpose keys derived from the signing root under fixed key identifiers | `internal/config`, `internal/services/keyring`, `internal/services/tokens` |
| Two access token classes, never interchangeable, each accepted only as the exact shape this service issues: its own key and key identifier, issuer, type, canonical non-nil identifiers, the one scope string for its class and audience, an application token's audience being the site and carrying a positive credential version, and a validity interval of exactly the access lifetime from the moment of issue | `internal/services/tokens`, `internal/web/authentication.go` |
| A developer application's credential version, refusing every token issued before its credential was reset | `internal/services/applications`, `internal/web/authentication.go` |
| The auth epoch every check is measured against, replaced transactionally to withdraw everything at once, after its row is locked `FOR UPDATE`; a migration replacing the epoch takes the same row lock first, and one changing login state, codes, sessions or revocations locks those tables in rotation's order | `internal/services/authority`, `internal/database/authorityrotation.go`, `internal/database/queries/credentials.sql`, `src/api/migrations/` |
| Login state that is opaque, single-use, browser-bound, application-bound, callback-exact and expiring, consumed by one `DELETE ... RETURNING` | `internal/services/oauth` |
| PKCE on every OAuth provider (Discord, GitHub, Google), with the verifier encrypted at rest; a Steam login holds no verifier | `internal/services/oauth` |
| Steam's OpenID 2.0 assertion checked before the login is spent: no repeated parameter; Steam's endpoint as `op_endpoint`; `return_to` the site's origin plus `/api/ui/steam-callback` with this request's state; `identity` equal to `claimed_id`, which is Steam's prefix and a non-zero unsigned 64-bit Steam ID in decimal; a signature covering `op_endpoint`, `claimed_id`, `identity`, `return_to` and `response_nonce`; and a `response_nonce` no more than thirty seconds ahead or the login lifetime plus thirty seconds behind. The realm is the site's origin plus `/` | `internal/services/providers/steam.go` |
| Steam's assertion then verified by Steam itself, once the login is spent: every returned `openid.*` field with only the mode replaced, posted to `https://steamcommunity.com/openid/login`, a constant no setting can move, through the bounded, non-redirecting client, accepted only on `is_valid:true`; no assertion or answer in an error or log | `internal/services/providers/steam.go`, `internal/web/providercallback.go` |
| A Steam account keyed by its Steam ID as decimal text, created with the username `steam:` plus that ID | `internal/services/accounts` |
| Google's exact issuer, an audience containing the client identifier, RS256 only, signature, nonce, and mandatory `exp` and `iat` within the clock skew; a non-empty `azp` equal to the client identifier when there are several audiences, and any other non-empty `azp` equal to it; a non-empty `at_hash` bound to the provider access token; `nbf` enforced whenever present; all against compiled-in endpoints a discovery document cannot move | `internal/services/providers/google.go` |
| Callback URI policy: absolute, HTTPS except on loopback where a port is required, no userinfo, no fragment, no control characters, reserved response keys refused at registration | `internal/urlpolicy` |
| A browser returned to the exact registered spelling, one encoded response parameter appended and no existing byte rewritten | `internal/urlpolicy`, `internal/web/providerlogin.go`, `providercallback.go` |
| Schema changed only by the pinned standalone Goose CLI, never by the service binary, which imports no Goose | `src/api/Dockerfile`, `scripts/check.sh` |
| One migration controller per Compose project: the `migrations` service on the internal database network alone, receiving only `GOOSE_DRIVER`, `GOOSE_MIGRATION_DIR`, a password-free `GOOSE_DBSTRING` and `PGPASSWORD`, run with `-env=none`, and never scaled or run beside another migration | `compose.yml`, `.env.sample` |
| An API that Compose starts only after the migration and provisioning exit successfully; one started against an unmigrated database grants nothing | `compose.yml`, `internal/web` |
| The site's application provisioned only where its configured identifier is absent: an owner holding no provider or password account, the application, and the callback derived from the validated site origin and the route table's `SiteEntryPath`, in one transaction whose identifier insert yields to a concurrent winner; an identifier already held is a no-op that changes nothing, whoever owns it; the generated credential stored at `HashCost` and discarded | `internal/services/siteapplication`, `cmd/abandonauth.go` |
| One `provisioning` service per Compose project, on the internal database network alone, receiving only `DATABASE_URL` and `DEBUG`, with non-secret identifier and origin as arguments, judging the origin with the parser `serve` uses, and printing only the identifier assignment | `compose.yml`, `internal/config`, `cmd/abandonauth.go` |
| Server-side sessions stored only as digests, absolute expiry, logout as a delete, double-submit CSRF with an exact `Origin` | `internal/services/sessions`, `internal/web/browsersession.go`, `cookies.go` |
| Budgets keyed by an authenticated user, counted in the database in windows the database clock decides, so every instance counts one user in one window, with no setting that raises or removes one | `internal/services/ratelimit`, `internal/database/queries/rate_limits.sql`, `internal/web/requestlimit.go` |
| One spelling of every address: a raw path carrying an escape, a repeated slash, a backslash or a dot segment is refused before CORS and before the router can decode or clean it into one that is served, and without a redirect to it; whether an address is declared is answered by the router that serves it | `internal/web/requesttarget.go`, `server.go` |
| An application's callback set replaced under its row lock, so two replacements arriving together leave one submitted set and never a mixture, and one arriving after the application is gone finds nothing | `internal/services/applications`, `internal/web/developerapplication.go` |
| A password sign-in that writes no cookie until the authority, the token and the session have all succeeded | `internal/web/passwordaccounts_devtools.go` |
| A recovered panic logged as the fact of a failure and the request it belonged to, never the recovered value, and never answered once a response has been committed or the connection taken | `internal/web/middleware.go` |
| Every transaction abandoned through one detached, bounded rollback, so a cancelled request cannot hold a connection or a lock | `internal/database/rollback.go` |
| Exactly one permitted origin, never a credentialed wildcard, with permission headers and preflight answers only for an address the route table names | `internal/web/cors.go` |
| Password sign-in compiled only into the development build and served only in debug mode on a loopback-only bind; a deployment refuses `DEBUG` outright | `internal/buildmode`, `internal/config`, the `_devtools.go` files |
| One hand-maintained schema, served as YAML and JSON only after it proves to be one complete mapping with no `example`, `examples` or `default` anywhere, refusals carrying fixed words that never quote the source; password operations documented in every build only when labelled `x-abandonauth-build: development`, while their routes and handlers are compiled out of a deployment, which answers both 404 | `internal/web/openapi.yaml`, `internal/web/apidocumentation.go`, `routes_devtools.go` |
| A log line that never carries a query string, header or cookie | `internal/logging` |
| An immutable RFC 6749 client type: a public client holds no credential (a database constraint ties a null credential to `public`), cannot authenticate, reset, or use the confidential sign-in, and is the only type the OIDC endpoints accept | `internal/services/applications`, `src/api/migrations/`, `internal/web/developerapplication.go`, `providerlogin.go` |
| Public-client redirects: portless `http` templates on an IPv4 loopback literal or `[::1]`, a path, no response keys; a request matches a template with exactly one numeric port added and nothing else changed; the exact spelling is stored and required again at redemption; nothing is redirected before client and redirect are proven | `internal/urlpolicy/nativecallback.go`, `internal/web/nativeauthorization.go` |
| OAuth input read whole or not at all: bounded bytes, fields and name length, no `;`, no encoded or case-varied names, no bad escape, control character or invalid UTF-8; recognized members at most once; query and form never merged; `token_type_hint` never read | `internal/web/request/oauthform.go` |
| One authorization root per public authorization, in one of 10,000 slots counted under a lock, with one absolute five-minute deadline; page handle, provider state, consent handle and code single-use digests bound to the browser's separate `abandonauth_native_oauth` cookie, the client, redirect, scopes, state, nonce, challenge and epoch | `internal/services/oauth/authorizationrequest.go`, `authorizationstate.go`, `internal/web/nativeauthorization.go`, `cookies.go` |
| Authentication separated from client authorization: a provider callback resolves the account and moves the root to `consent` under the auth-epoch lock and creates no code, session, relationship or token; only `POST /api/oauth/consent/{consent}/allow`, with the exact site `Origin` checked before the handle and the binding cookie, creates a code. The consent handle is 32 random bytes under its own digest domain and stage, handed over only in a fragment, and neither handle satisfies the other's lookup. Allow and Cancel lock one row, so exactly one wins and every loser is one fixed 404. Consent is asked every time, is all-or-nothing, and always discloses the cross-application user ID, the username only under `profile` and the 90-day session only under `offline_access`. Cancel leaves the client nothing, while an account a first sign-in created stays by explicit decision | `internal/services/oauth/authorizationrequest.go`, `internal/services/credentials`, `internal/web/providerlogin.go`, `internal/web/nativeauthorization.go`, `src/api/migrations/`, `src/website/app/pages/consent.vue` |
| PKCE `S256` mandatory; a code redeemed by one delete only when client, redirect, epoch and the verifier's challenge all match, so a wrong attempt leaves it; issuance under the shared auth-epoch lock in one transaction with signing | `internal/services/oauth/authorizationcode.go`, `internal/web/nativetoken.go` |
| Two RS256 key files, one per token class, PKCS #8 of at least 2048 bits, `kid` the RFC 7638 thumbprint, never the same key; two published key sets; ID and access tokens each accepted only in their exact profile with no clock tolerance | `internal/services/oidc`, `internal/config`, `internal/web/oidcdiscovery.go` |
| Public OIDC subjects: `sub` is the user's canonical lower-case non-nil `User.id`, deliberately the same at every application and equal to the user access token's `sub`, released under `openid` without `profile`, with no `user_id` claim; issuers refuse the nil UUID, and the access token verifier and the test validators refuse any other spelling, a member named twice and trailing JSON. The subject grants nothing on its own: UserInfo and revocation resolve it only together with the token's exact client to one `oauth_public_client_user` row, which is never logged and is kept across rotation as a lock anchor, not a credential | `internal/services/oidc`, `internal/services/oauth/clientuser.go`, `internal/web/nativeuserinfo.go`, `nativerevocation.go`, `internal/web/servertest/oidcclient.go` |
| Rotating refresh tokens with reuse revoking the family, ten families per person and application counted under that pair's `oauth_public_client_user` row lock, ten thousand members per family, no scope widening, and no rotation once the pair's row is gone | `internal/services/oauth/refreshtoken.go`, `authorizationcode.go` |
| UserInfo and revocation accepting only the OIDC access token class; a thousand unexpired revocations per person and application, counted under the exact pair's row lock, beyond which revocation answers 503 rather than claiming success; a token naming a deleted user, a deleted client or a pair with no row revoking nothing and answered like an unknown token; a resource server's local acceptance up to fifteen minutes after withdrawal documented as the profile's limit | `internal/web/nativeuserinfo.go`, `nativerevocation.go`, `internal/services/oauth/clientuser.go`, `docs/INSTALLED-CLIENT-OIDC.md` |
| At most 64 public-protocol requests per process, provider callbacks included and admitted before their state is read, refused at once with a fixed answer | `internal/web/publicprotocol.go` |
| Authorization and consent page answers never cached or framed; the site's `/authorize` and `/consent` documents are `Referrer-Policy: same-origin`, so their form POSTs carry the exact site `Origin` and no cross-origin request receives a referrer, while the API's authorization and consent answers and 303 redirects stay `no-referrer`; OAuth answers `no-store` and `Pragma: no-cache`; no cross-origin permission on any public-client address | `internal/web/response/oauth.go`, `cors.go`, `routes.go`, `src/website/server/utils/authorizationHeaders.ts` |
| A consent failure logged only as the fixed public-client failure, its request identifier and the matched route pattern: never the error, target, handle, cookie, application name, user, scopes or anything the request carried | `internal/web/nativeauthorization.go`, `internal/web/middleware.go` |

## Where the negative tests are

A change to a control above extends these rather than replacing them:

- `internal/web/requesttarget_test.go`, `index_integration_test.go` — target
  spellings that reach nothing, that a browser is told nothing about and that
  are never redirected to the address they would have been cleaned into; an
  escaped query on an exact address is the positive control.
- `internal/web/cors_integration_test.go` — preflights and origin permission for
  addresses this service does not serve, from the site and from elsewhere.
- `internal/web/googleidentity_integration_test.go` — the identity tokens Google
  must be refused for, with a positive control against vacuous refusal.
- `internal/web/providerlogin_integration_test.go`,
  `providercallback_integration_test.go` — state missing, altered, replayed,
  from another browser, for another provider or another application; the site's
  application accepting only its exact registered callback; and refused target
  spellings spending neither the login nor the one-time code they carry. For
  Steam besides: the OpenID request, an assertion moved to another login,
  malformed callbacks spending no login and asking Steam nothing, a refused
  assertion spending the login after one verification, and no assertion value
  in the log.
- `internal/services/providers/steam_test.go` — every binding, signed-field,
  Steam ID and nonce refusal with its boundaries, every unacceptable
  verification answer, redirects, unreachable and stalled verification, and
  the address and form Steam is asked with, extension fields included, with a
  genuine assertion as the positive control.
- `internal/web/provideridentity_integration_test.go` — Steam IDs that are
  zero, signed, padded, overflowing or not decimal signing nobody in.
- `internal/web/unavailable_integration_test.go` — every endpoint refusing when
  the database cannot be reached, a genuine token refused rather than
  accepted on its signature alone, and genuine sessions, tokens, codes, logins
  and application credentials granting nothing and naming nothing from the
  database when it answers with an empty schema.
- `internal/database/authorityrotation_integration_test.go` — a rotation
  waiting on a held auth-epoch row, abandoned while waiting without changing
  anything, and completing in full once the row is released.
- `cmd/operations_integration_test.go` — serving leaving a migrated database and
  an empty one exactly as found; provisioning creating once and changing nothing
  the second time, refusing an unmigrated database, and failing against an
  unreachable one without its password.
- `cmd/provision_test.go`, `cmd/secretsource_test.go` — provisioning's two input
  modes, one flag without the other, malformed and nil identifiers, unsafe and
  credential-carrying origins, stray arguments, the build's transport rule, a
  `--database-url` refused, and none of those values in errors or output.
- `internal/services/siteapplication/siteapplication_integration_test.go` — an
  owner no one can sign in as, the credential at `HashCost`, an identifier
  already held by a login account left with its owner, callbacks, credential and
  every power over it, a concurrent winner leaving one complete set, and a
  cancelled provisioning leaving nothing.
- `cmd/environmentsample_test.go` — the sample migration connection carrying no
  password.
- `scripts/migrationcheck.sh` — concurrent `up` requests converging on one
  migration, a failed migration leaving provisioning and the API never started,
  and a sentinel password in neither Goose's arguments nor its log, with the
  migration container's settings held to its allowlist; refused provisioning
  inputs starting no API, writing no row and repeated in no log; provisioning
  finishing before the API starts, writing the exact callback for an origin with
  or without a trailing slash, changing nothing when run again, carrying no
  database connection in its arguments, and held to its own allowlist.
- `scripts/containercheck.sh` — the migration lifecycle on the template: a
  no-op second up, offline grants and revocations anchored to the
  public-client/user row, one down removing the public-client layer, the next
  removing the Steam layer and its accounts, the next
  removing exactly the auth-state layer, `down-to 0` removing the baseline, and
  up rebuilding the schema every test is cloned from.
- `internal/web/requestlimit_integration_test.go` — the developer application
  budget stated as the number the service promises and shared across every
  change, one user's spent budget leaving another served, a forwarding header
  varied per request neither renewing a user's budget nor spending a
  bystander's, and no user identifier stored in clear.
- `internal/services/ratelimit/ratelimit_integration_test.go` — two limiters
  sharing one database window, a refusal's wait as whole positive seconds
  within the window, identities kept apart, unknown groups refused, and the
  sweep removing only ended windows.
- `internal/services/tokens/tokens_test.go` — the token abuse matrix for both
  classes: altered scopes, identifiers, audiences, credential versions and
  validity intervals, with the shapes this service issues as positive controls.
- `internal/web/developerapplication_integration_test.go` — two callback
  replacements forced to overlap at the row lock leaving exactly one submitted
  set, and one that outlives its application finding nothing.
- `internal/web/passwordsignintest/` — a password accepted and then the
  authority unreadable granting no cookie, token or stored session.
- `internal/web/servercomposition_test.go` — a panic's value in neither the
  response nor the log, and nothing appended after a write, a flush or a
  hijack.
- `internal/database/rollback_integration_test.go`,
  `internal/services/accounts/accounts_integration_test.go` — a cancelled
  transaction rolled back within the bound, leaving no row and no lock.
- `internal/web/browsersession_integration_test.go` — cookie attributes, CSRF,
  logout, a copied cookie after logout.
- `internal/web/passwordaccounts_default_integration_test.go` — a deployment
  serving neither account-seeding address.
- `internal/web/passwordsignintest/` — the development build's counterpart:
  the journeys through reachability, session and CSRF behaviour, a refusal that
  says nothing about the account, the password at rest at `HashCost`,
  CORS and log redaction. The route, handler and schema declarations that build
  carries are proved by the build-neutral tests in `internal/web` run under
  `-tags=devtools`.
- `internal/web/passwordroutes_default_test.go`,
  `apidocumentation_default_test.go`, `apidocumentation_integration_test.go` — a
  deployment declaring no password route, documenting both password operations
  only with the development label and their 404, and answering both 404.
- `internal/web/apischema_test.go` — the schema agreeing with the route table
  in both directions, user and application token schemes never swapped, Origin
  and CSRF never unconditionally required where a token is accepted, the
  sign-in, session, Google and Steam wording, PKCE claimed only for the OAuth
  providers, references resolving, and no credential,
  example or default in either representation.
- `internal/web/apidocumentation_test.go` — malformed, multi-document,
  incomplete and example-bearing sources refused for both representations, with
  a sentinel in neither the response, the error nor the log.
- `internal/web/developerapplication_integration_test.go` — an unknown
  application refused in the same words as a wrong credential, for a valid
  credential, the published comparison input, an empty and an overlength one,
  with no token or session granted.
- `internal/services/applications/credentialhash_test.go` — the comparison hash
  an unknown application is checked against is bcrypt at `HashCost`, made from
  its published input.
- `internal/urlpolicy/nativecallback_test.go` — loopback templates and redirects
  in every refused spelling: abbreviated, integer, octal and mapped addresses,
  zone identifiers, host names, ports, dot segments, escapes and response keys.
- `internal/web/request/oauthform_test.go`, `nativeauthorization_test.go`,
  `nativetoken_test.go` — the parser-differential matrix, every bound at its
  limit and one past it, PKCE, state, nonce and opaque-value syntax, and
  `token_type_hint` ignored in every form.
- `internal/web/nativeauthorization_integration_test.go` — no redirect before
  client and redirect are proven, the fragment handoff, Origin and binding
  refusals consuming nothing, one winner of racing choices, the separate cookie,
  capacity and recovery, hostile application names; for consent, the exact model
  for every scope set, a code only on Allow, Cancel granting nothing and keeping
  the account, Origin refused before the handle and binding refused consuming
  nothing, page and consent handles never interchangeable, one winner of racing
  answers, expiry, a code cut short by the deadline, a deleted person or
  application, and a forced failure's log carrying none of what it handled.
- `internal/web/providercallback_integration_test.go` — a public sign-in reaching
  only the fragment-only consent handoff with no code, relationship, session or
  grant on every provider, its callback spent once, and refusal, cancellation,
  an unusable identity and an internal failure returning directly to the client
  without consent.
- `src/website/test/authorizationPage.spec.ts`, `consentPage.spec.ts`,
  `loginPage.spec.ts`, `authorizationHeaders.spec.ts` — provider selection drawn
  as the login page is and disclosing no scope, the exact conditional consent
  copy, unknown, duplicate and noncanonical scopes failing closed, empty forms,
  hostile names, fragment and query abuse asking the API nothing, invalid and
  elapsed deadlines, actions removed when the deadline arrives, and the document
  headers on exact paths only.
- `internal/web/nativetoken_integration_test.go`,
  `nativeuserinfo_integration_test.go`, `nativerevocation_integration_test.go`,
  `oidcdiscovery_integration_test.go` — exact token profiles validated from
  discovery alone, code binding and replay, racing redemption, refresh rotation,
  reuse and narrowing, one canonical UUID subject across a confidential
  application and two public clients, refresh and UserInfo with another
  provider account another UUID, non-canonical, nil, unknown and unserved
  subjects refused at UserInfo and by the validators, duplicate members and
  trailing JSON under each genuine key, the JOSE and claim abuse matrix,
  cross-purpose forgeries with each key, credential-class swaps, revocation
  indistinguishability, its ceiling and its no-op for deleted users, deleted
  clients and unserved subjects, every endpoint failing closed without the
  public-client/user table while the confidential flow continues, zero clock
  tolerance, and local acceptance continuing after withdrawal.
- `internal/services/oidc/oidc_test.go` — the nil subject never signed, the
  canonical spelling issued, and missing, repeated, wrong-type, nil,
  upper-case, braced, compact, URN, malformed and opaque subjects and trailing
  JSON refused under the genuine access key, with a re-signed canonical subject
  as the positive control.
- `internal/web/publicprotocol_test.go`, `publicprotocol_integration_test.go` —
  the 64-permit bound, permits returned after panic and cancellation, and a
  callback or consent answer refused while every permit is held spending nothing
  and succeeding on retry.
- `internal/database/nativeauthorization_integration_test.go` — lock ordering
  against rotation, a consent answer and a callback waiting on a rotation granting
  nothing, consent values existing only at the consent stage, the person and
  authentication time moving onto the code only on Allow, a failed approval
  leaving the consent usable, the capacity, family and revocation ceilings under races,
  racing issuances converging on one public-client/user row with every other
  pair kept apart, revocation and holder lookups only for the exact pair, a
  removed relationship granting and recording nothing, a redemption that
  cannot record the relationship keeping its code and no offline grant, and the
  null-credential constraint.

Credential hashing is one production path: `credentials.Hash` creates bcrypt at
`credentials.HashCost` and `credentials.Matches` verifies it, and neither takes
a factor. `applications.New` accepts a `CredentialHasher` whose nil value is
that path, so `cmd/operations.go`, which names none, stores at `HashCost`; the
guard is `internal/services/applications/credentialhash_test.go`, and the
factor itself is asserted in `internal/services/credentials/credentials_test.go`.
The only other implementation is `servertest.testHasher`, set through
`web.Dependencies.CredentialHasher` by the test harness alone; no binary imports
that package.
`applications.Authenticate` refuses an empty or overlength credential before
looking the identifier up, then compares a valid one against either the stored
hash or a fixed comparison hash at `HashCost`, and only then combines that
result with whether the application exists. The comparison hash is valid from
process start, so the first unknown request creates nothing, and the input it
was made from is published because matching it grants nothing.
