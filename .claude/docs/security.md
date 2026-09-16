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
  is readable by every process on the machine.
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
- Rate-limit login, callback, token exchange, credential reset, account creation
  and linking, and recovery, accounting for distributed attacks and avoiding
  account enumeration.
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
| The auth epoch every check is measured against, replaced transactionally to withdraw everything at once | `internal/services/authority`, `internal/database/authorityrotation.go` |
| Login state that is opaque, single-use, browser-bound, application-bound, callback-exact and expiring, consumed by one `DELETE ... RETURNING` | `internal/services/oauth` |
| PKCE on every provider, with the verifier encrypted at rest | `internal/services/oauth` |
| Google's issuer, audience and `azp`, RS256 only, signature, nonce, `at_hash` and clock claims, against compiled-in endpoints a discovery document cannot move | `internal/services/providers/google.go` |
| Callback URI policy: absolute, HTTPS except on loopback where a port is required, no userinfo, no fragment, no control characters, reserved response keys refused at registration | `internal/urlpolicy` |
| A browser returned to the exact registered spelling, one encoded response parameter appended and no existing byte rewritten | `internal/urlpolicy`, `internal/web/providerlogin.go`, `providercallback.go` |
| A database migrated only when empty, or carrying both this service's migration history and the marker its baseline writes; every other state refused without being changed | `internal/database/schemastate.go`, `migrate.go` |
| Server-side sessions stored only as digests, absolute expiry, logout as a delete, double-submit CSRF with an exact `Origin` | `internal/services/sessions`, `internal/web/browsersession.go`, `cookies.go` |
| Budgets keyed so a public identifier cannot lock anyone out, counted in the database in windows the database clock decides, so every instance counts one client in one window, with no setting that raises or removes one | `internal/services/ratelimit`, `internal/database/queries/rate_limits.sql`, `internal/web/requestlimit.go` |
| One spelling of every address: a raw path carrying an escape, a repeated slash, a backslash or a dot segment is refused before CORS and before the router can decode or clean it into one that is served, and without a redirect to it; whether an address is declared is answered by the router that serves it | `internal/web/requesttarget.go`, `server.go` |
| Forwarding headers believed only from a configured proxy, which is who a request came from and not what it asked for; the forwarded chain is read from its trusted end across every header line, so a value the client prepended is never the address it is counted as, and a chain that cannot be read in full falls back to the peer rather than to `X-Real-IP` | `internal/web/clientaddress.go` |
| An application's callback set replaced under its row lock, so two replacements arriving together leave one submitted set and never a mixture, and one arriving after the application is gone finds nothing | `internal/services/applications`, `internal/web/developerapplication.go` |
| A password sign-in that writes no cookie until the authority, the token and the session have all succeeded | `internal/web/passwordaccounts_devtools.go` |
| A recovered panic logged as the fact of a failure and the request it belonged to, never the recovered value, and never answered once a response has been committed or the connection taken | `internal/web/middleware.go` |
| Every transaction abandoned through one detached, bounded rollback, so a cancelled request cannot hold a connection or a lock | `internal/database/rollback.go` |
| Exactly one permitted origin, never a credentialed wildcard, with permission headers and preflight answers only for an address the route table names | `internal/web/cors.go` |
| Password sign-in compiled only into the development build and served only in debug mode on a loopback-only bind; a deployment refuses `DEBUG` outright | `internal/buildmode`, `internal/config`, the `_devtools.go` files |
| A published schema narrowed to the addresses the running build serves, because the annotations it is generated from carry no build constraints | `internal/web/apidocumentation.go` |
| A log line that never carries a query string, header or cookie | `internal/logging` |

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
  application accepting only its exact registered callback; and more refused
  target spellings than a budget allows, spending neither the login or one-time
  code they carry nor the budget.
- `internal/web/unavailable_integration_test.go` — every endpoint refusing when
  the database cannot be reached, and a genuine token refused rather than
  accepted on its signature alone.
- `internal/web/requestlimit_integration_test.go` — budgets stated as the
  numbers the service promises, proof that spending one against a public
  application identifier does not lock it out, that a forwarding header is
  believed only from the proxy, and that a client prepending to the forwarded
  chain, on the same line or its own, still has the one budget the proxy's
  appended address gives it.
- `internal/web/clientaddress_test.go` — the forwarded chain read from its
  trusted end: untrusted peers, one and several trusted hops, all-trusted
  chains, IPv4-mapped addresses, and every unreadable chain falling back to the
  peer and never to `X-Real-IP`.
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
  says nothing about the account, the password at rest at `HashCost`, budgets,
  CORS and log redaction. The route, handler and schema declarations that build
  carries are proved by the build-neutral tests in `internal/web` run under
  `-tags=devtools`.
- `internal/web/passwordroutes_default_test.go`,
  `apidocumentation_default_test.go` — a deployment declaring no password route
  and publishing none.
- `internal/web/apidocumentation_test.go` — the published schema agreeing with
  the reference for the build that produced it, and refusing to publish a
  document it cannot narrow.
- `internal/web/developerapplication_integration_test.go` — an unknown
  application refused in the same words as a wrong credential, for a valid
  credential, the published comparison input, an empty and an overlength one,
  with no token or session granted.
- `internal/services/applications/credentialhash_test.go` — the comparison hash
  an unknown application is checked against is bcrypt at `HashCost`, made from
  its published input.

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
