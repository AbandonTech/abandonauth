# Security

Authentication, authorization, OAuth/OIDC, token, session, redirect,
credential, account-linking, and cryptographic changes require a sensitive
plan and review by `abandonauth-security-reviewer` before implementation.

## Secret handling

- Never read real `.env` files or local credentials. Read `.env.sample` only.
- Never expose passwords, client secrets, authorization codes, JWTs, provider
  access tokens, refresh tokens, session cookies, or private keys in output,
  logs, URLs, exceptions, plans, tests, fixtures, snapshots, or commits.
- Hold secrets in `config.Secret` and call `Reveal()` only at the narrow
  outbound call or cryptographic boundary that requires the value.
- `DATABASE_URL`, `JWT_SECRET` and the three provider client secrets are read
  from the environment only. Do not give any of them a command-line flag: an
  argument is readable by every process on the machine.
- Redact authorization headers, cookies, query strings, and provider response
  bodies from logging and telemetry.

Repository permission denials are defense in depth, not a complete sandbox.
Claude Code's native Windows Bash can read files through arbitrary subprocesses
despite `Read` denials. Run implementation from a secret-free checkout or WSL2
with Claude's sandbox enabled when secret isolation must be enforced. Never
place production credentials in an agent-accessible development worktree.

## OAuth and OIDC

- Bind state to the initiating browser session, make it unpredictable and
  single-use, enforce expiration, and use constant-time verification where
  applicable. State is not a container for trusted comma-delimited input.
- Require PKCE for public clients and record why any confidential-client flow
  omits it. Validate nonce for OIDC responses.
- Match registered redirect URIs exactly. Define HTTPS requirements and only
  narrowly scoped loopback exceptions. Do not normalize, prefix-match, or use
  caller-controlled redirects.
- Never place access, refresh, exchange, or session tokens in redirect query
  strings. Authorization codes must be short-lived, one-time, audience-bound,
  and stored atomically in a shared expiring store.
- Validate provider issuer, client/audience, signature, algorithm, nonce, and
  required claims. Do not treat user-info responses as sufficient proof when
  the protocol requires ID-token validation.
- Account linking requires recent authentication and proof that the external
  identity belongs to the current user. Avoid automatic linking by mutable or
  unverified attributes.

## Tokens and sessions

- Explicitly allowlist signing algorithms; never derive accepted algorithms
  from token input.
- Validate issuer, audience, subject, expiration, not-before, issued-at, token
  type, and required claims. Use exact scope/set membership.
- Separate signing keys, audiences, claims, dependencies, and storage for user,
  developer application, exchange, access, refresh, and session credentials.
- Access credentials are short-lived. Rotation, revocation, key IDs, JWKS,
  replay detection, and refresh-token reuse behavior are explicit design
  decisions.
- One-time credentials must be consumed atomically and work correctly across
  workers. In-memory process state is not a distributed replay defense.
- Browser authentication should use `HttpOnly`, `Secure`, and appropriate
  `SameSite` cookies. Cookie-authenticated state changes require CSRF defense.
  Logout and credential reset must invalidate server-side authority.

## Authorization and abuse controls

- Deny by default and perform authorization on every protected resource.
- Use exact identifiers, scopes, roles, and ownership comparisons. Do not use
  substring checks for permissions.
- Prevent identifier probing through consistent authorization and not-found
  behavior where appropriate.
- Rate-limit login, callback, token exchange, credential reset, account
  creation/linking, and recovery endpoints. Consider distributed attacks and
  avoid account enumeration.
- Debug authentication routes, wildcard CORS, and verbose errors must be
  unreachable in production even when configuration is mistaken.

## The controls in force, and where they live

These are decisions, not incidental behaviour. Weakening one is a security
change: it needs a sensitive plan, a review, and abuse-case tests, whatever else
the work was about.

| Control | Where |
| --- | --- |
| Exactly `HS512`, checked rather than obeyed; per-purpose keys derived from the signing root under fixed key identifiers | `internal/config`, `internal/services/keyring`, `internal/services/tokens` |
| Two access token classes that are never interchangeable, each validated against its own issuer, audience, subject, scope, type and lifetime | `internal/services/tokens`, `internal/web/authentication.go` |
| A developer application's credential version, which refuses every token issued before its credential was reset | `internal/services/applications`, `internal/web/authentication.go` |
| The auth epoch every check is measured against, replaced transactionally to withdraw everything at once | `internal/services/authority`, `internal/database/authorityrotation.go` |
| Login state that is opaque, single-use, browser-bound, application-bound, callback-exact and expiring, consumed by one `DELETE ... RETURNING` | `internal/services/oauth` |
| PKCE on every provider, with the verifier encrypted at rest | `internal/services/oauth` |
| Google's issuer, audience and `azp`, RS256 only, signature, nonce, `at_hash` and clock claims, against compiled-in endpoints a discovery document cannot move | `internal/services/providers/google.go` |
| Callback URI policy: absolute, HTTPS except on loopback where a port is required, no userinfo, no fragment, no control characters, reserved response keys refused at registration | `internal/urlpolicy` |
| A browser returned to the exact registered spelling, with one encoded response parameter appended and no existing byte rewritten | `internal/urlpolicy`, `internal/web/providerlogin.go`, `providercallback.go` |
| A database migrated only when it is empty or carries both this service's migration history and the marker its baseline writes; every other state refused without being changed | `internal/database/schemastate.go`, `migrate.go` |
| Server-side sessions stored only as digests, absolute expiry, logout as a delete, double-submit CSRF with an exact `Origin` | `internal/services/sessions`, `internal/web/browsersession.go`, `cookies.go` |
| Budgets keyed so a public identifier cannot lock anyone out, counted in the database, with no setting that raises or removes one | `internal/services/ratelimit`, `internal/web/requestlimit.go` |
| One spelling of every address: a raw request path carrying an escape, a repeated slash, a backslash or a dot segment is refused before CORS and before the router can decode or clean it into one that is served, and without a redirect to it | `internal/web/requesttarget.go`, `server.go` |
| Forwarding headers believed only from a configured proxy, which is who a request came from and not what it asked for | `internal/web/clientaddress.go` |
| Exactly one permitted origin, never a credentialed wildcard, and permission headers and preflight answers only for an address the route table names | `internal/web/cors.go` |
| Password sign-in compiled only into the development build, and served only in debug mode on a loopback-only bind; a deployment refuses `DEBUG` outright | `internal/buildmode`, `internal/config`, the `_devtools.go` files |
| A published schema narrowed to the addresses the running build serves, because the annotations it is generated from carry no build constraints | `internal/web/apidocumentation.go` |
| A log line that never carries a query string, header or cookie | `internal/logging` |

## Where the negative tests are

A change to any of the above is expected to extend these rather than replace
them:

- `internal/web/requesttarget_test.go`, `index_integration_test.go` — the target
  spellings that reach nothing, that a browser is told nothing about and that
  are never redirected to the address they would have been cleaned into, with an
  escaped query on an exact address as the positive control.
- `internal/web/cors_integration_test.go` — preflights and origin permission for
  addresses this service does not serve, from the site and from elsewhere.
- `internal/web/googleidentity_integration_test.go` — the identity tokens Google
  must be refused for, with a positive control so the refusals cannot pass
  vacuously.
- `internal/web/providerlogin_integration_test.go`,
  `providercallback_integration_test.go` — state that is missing, altered,
  replayed, from another browser, for another provider or another application;
  the site's application accepting only its exact registered callback; and more
  refused target spellings than a budget allows spending neither the login or
  one-time code they carry nor the budget.
- `internal/web/unavailable_integration_test.go` — every endpoint refusing when
  the database cannot be reached, and a genuine token refused rather than
  accepted on its signature alone.
- `internal/web/requestlimit_integration_test.go` — budgets, and proof that
  spending one against a public application identifier does not lock it out.
- `internal/web/browsersession_integration_test.go` — cookie attributes, CSRF,
  logout, and a copied cookie after logout.
- `internal/services/tokens/tokens_test.go` — the token abuse matrix.
- `internal/web/passwordaccounts_default_integration_test.go` — a deployment
  serving neither of the account-seeding addresses.
- `internal/web/apidocumentation_test.go` — the published schema naming password
  sign-in only in the build that serves it, and refusing to publish a document
  it cannot narrow.
