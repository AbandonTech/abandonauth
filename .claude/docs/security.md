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
| Two access token classes, never interchangeable, each validated against its own issuer, audience, subject, scope, type and lifetime | `internal/services/tokens`, `internal/web/authentication.go` |
| A developer application's credential version, refusing every token issued before its credential was reset | `internal/services/applications`, `internal/web/authentication.go` |
| The auth epoch every check is measured against, replaced transactionally to withdraw everything at once | `internal/services/authority`, `internal/database/authorityrotation.go` |
| Login state that is opaque, single-use, browser-bound, application-bound, callback-exact and expiring, consumed by one `DELETE ... RETURNING` | `internal/services/oauth` |
| PKCE on every provider, with the verifier encrypted at rest | `internal/services/oauth` |
| Google's issuer, audience and `azp`, RS256 only, signature, nonce, `at_hash` and clock claims, against compiled-in endpoints a discovery document cannot move | `internal/services/providers/google.go` |
| Callback URI policy: absolute, HTTPS except on loopback where a port is required, no userinfo, no fragment, no control characters, reserved response keys refused at registration | `internal/urlpolicy` |
| A browser returned to the exact registered spelling, one encoded response parameter appended and no existing byte rewritten | `internal/urlpolicy`, `internal/web/providerlogin.go`, `providercallback.go` |
| A database migrated only when empty, or carrying both this service's migration history and the marker its baseline writes; every other state refused without being changed | `internal/database/schemastate.go`, `migrate.go` |
| Server-side sessions stored only as digests, absolute expiry, logout as a delete, double-submit CSRF with an exact `Origin` | `internal/services/sessions`, `internal/web/browsersession.go`, `cookies.go` |
| Budgets keyed so a public identifier cannot lock anyone out, counted in the database, with no setting that raises or removes one | `internal/services/ratelimit`, `internal/web/requestlimit.go` |
| One spelling of every address: a raw path carrying an escape, a repeated slash, a backslash or a dot segment is refused before CORS and before the router can decode or clean it into one that is served, and without a redirect to it | `internal/web/requesttarget.go`, `server.go` |
| Forwarding headers believed only from a configured proxy, which is who a request came from and not what it asked for | `internal/web/clientaddress.go` |
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
- `internal/web/requestlimit_integration_test.go` — budgets, and proof that
  spending one against a public application identifier does not lock it out.
- `internal/web/browsersession_integration_test.go` — cookie attributes, CSRF,
  logout, a copied cookie after logout.
- `internal/services/tokens/tokens_test.go` — the token abuse matrix.
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
`credentials.HashCost` and `credentials.Matches` verifies it. No build carries
another work factor, a `Hasher` value or an injected implementation, so a test
cannot be composed with a cheaper one; the deployed factor is asserted in
`internal/services/credentials/credentials_test.go`.
`applications.Authenticate` refuses an empty or overlength credential before
looking the identifier up, then compares a valid one against either the stored
hash or a fixed comparison hash at `HashCost`, and only then combines that
result with whether the application exists. The comparison hash is valid from
process start, so the first unknown request creates nothing, and the input it
was made from is published because matching it grants nothing.
