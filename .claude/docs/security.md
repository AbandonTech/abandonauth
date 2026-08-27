# Security

Authentication, authorization, OAuth/OIDC, token, session, redirect,
credential, account-linking, and cryptographic changes require a sensitive
plan and review by `abandonauth-security-reviewer` before implementation.

## Secret handling

- Never read real `.env` files or local credentials. Read `.env.sample` only.
- Never expose passwords, client secrets, authorization codes, JWTs, provider
  access tokens, refresh tokens, session cookies, or private keys in output,
  logs, URLs, exceptions, plans, tests, fixtures, snapshots, or commits.
- Use `SecretStr` or equivalent secret-bearing types and reveal values only at
  the narrow outbound call or cryptographic boundary that requires them.
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
- Debug authentication routes, wildcard CORS, documentation, and verbose errors
  must be unreachable in production even when configuration is mistaken.

## Current high-risk areas

Plans touching these areas must verify current behavior rather than assuming
it is safe:

| Area | Current concern |
| --- | --- |
| `dependencies/auth/jwt.py` | decode does not explicitly allowlist algorithms; audience can be skipped; scope uses substring membership; exchange-token cache is process-local and not consumed on exchange |
| `routers/ui.py` and `pages/login.vue` | OAuth state is not session-bound or unpredictable; exchange credentials are redirected in query strings |
| `routers/google.py` | caller-controlled redirect target and fixed fake audience bypass the registered callback flow |
| `routers/developer_application.py` | endpoint documented as short-lived issues a long-lived JWT; callback URI strings lack scheme and policy validation |
| `routers/ui.py` and website auth | long-lived JWT is readable by browser JavaScript and logout has no server-side revocation |
| `routers/password_login.py` and `main.py` | debug configuration enables authentication routes and wildcard CORS |

Do not opportunistically change these behaviors in unrelated work. Address
them through reviewed plans with regression and abuse-case tests.
