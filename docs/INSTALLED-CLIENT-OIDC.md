# Signing people in to an installed application

This guide is for an application installed and run on a person's own device,
such as a desktop or command-line application, that signs the person in with
AbandonAuth. It cannot keep a secret from the person running it, so it is a
**public client** (RFC 6749) and authenticates with no credential at all. It
uses OpenID Connect Authorization Code flow with PKCE `S256` through the
operating system's browser and a loopback redirect, as OAuth 2.0 for Native Apps
(RFC 8252) describes.

A server-side application that can protect a credential is a confidential
client instead and uses the exchange in the [README](../README.md#the-exchange).

The protocol is defined by OAuth 2.0 (RFC 6749), PKCE (RFC 7636), RFC 8252,
OAuth Authorization Server Metadata (RFC 8414), Authorization Server Issuer
Identification (RFC 9207), the JWT Access Token Profile (RFC 9068), Token
Revocation (RFC 7009), the OAuth 2.0 Security Best Current Practice (RFC 9700),
and OpenID Connect Core and Discovery. The exact contract of every endpoint is
the OpenAPI document AbandonAuth serves at `/api/openapi.yaml`.

## Register the application

1. In the AbandonAuth site, open `Developer Applications` and create an
   application with the client type **Public client**. The type can never be
   changed; a public client receives no credential.
2. Register its loopback redirect templates, without a port:
   `http://127.0.0.1/oauth/callback` and `http://[::1]/oauth/callback`. A
   template must use `http`, the IPv4 loopback literal or `[::1]` (never a host
   name such as `localhost`), a non-empty path, no user information or fragment,
   and none of the query keys `code`, `state`, `error`, `error_description` or
   `iss`.

The application's identifier is its `client_id`. It is not a secret, and the
application embeds nothing else: never put a credential of any kind in an
installed application.

## Configure the issuer, then discover everything else

Pin exactly one setting in the application: the issuer, which is AbandonAuth's
origin followed by `/api`, such as `https://auth.abandontech.cloud/api`.

Fetch `<issuer>/.well-known/openid-configuration` and require its `issuer`
member to equal the pinned issuer byte for byte before trusting anything it
names. Take every endpoint from it:

| Member | Use |
| --- | --- |
| `authorization_endpoint` | where the browser is opened |
| `token_endpoint` | code redemption and refresh |
| `userinfo_endpoint` | the person's current claims |
| `revocation_endpoint` | revoking a refresh or access token |
| `jwks_uri` | the key set that verifies **ID tokens only** |
| `access_token_jwks_uri` | the key set that verifies **access tokens only** |

The two key sets are deliberately separate. Never try a key from one set
against the other class of token.

## Sign a person in

1. **Draw fresh values for this attempt** from a cryptographically secure
   random source: `state` and `nonce`, each 32 random bytes as 43 unpadded
   base64url characters, and a PKCE `code_verifier` of 43 to 128 unreserved
   characters (32 random bytes as base64url is a good choice). The
   `code_challenge` is the unpadded base64url SHA-256 of the verifier. Keep all
   three in memory for this attempt only.
2. **Open the loopback listener immediately before authorizing.** Bind it only
   to `127.0.0.1` or `::1`, never to every interface. Prefer a port the
   operating system assigns. Try IPv4 and IPv6 without assuming either is
   present. The redirect is the registered template with the listener's port
   added, such as `http://127.0.0.1:53124/oauth/callback`; nothing else may
   differ.
3. **Open the system browser** at the authorization endpoint with exactly one of
   each: `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`,
   `nonce`, `code_challenge` and `code_challenge_method=S256`. Never use an
   embedded web view. `scope` is `openid`, optionally with `profile` and
   `offline_access`. The query is at most 8,192 bytes.
4. **The person signs in, then decides.** AbandonAuth shows the standard sign-in
   page with the registered application name and asks the person to choose
   Discord, GitHub, Google or Steam; the application cannot choose the provider.
   Once the provider has authenticated them, AbandonAuth shows a separate
   approval screen that names the application and says what it is asking for:

   - always, `Identify you with your AbandonAuth user ID. This ID is the same
     for every application.`
   - with `profile`, `See your AbandonAuth username.`
   - with `offline_access`, `Keep you signed in for up to 90 days.`

   The screen offers `Allow` and `Cancel`, and it asks every time: approval is
   never remembered, and nothing is approved silently. Only `Allow` creates the
   code your listener receives; `Cancel` answers `access_denied` and leaves your
   application nothing. A first sign-in creates the person's AbandonAuth account
   before this screen, and that account stays whichever they choose. The person
   has five minutes from the authorization request for the whole of this step,
   and neither signing in nor approving extends it.
5. **Accept exactly one answer on the listener.** Accept a request only to the
   exact redirect path. Refuse an answer that repeats `code`, `state`, `iss` or
   `error`, carries both `code` and `error`, or lacks `state` or `iss`. Require
   `state` to equal this attempt's state and `iss` to equal the pinned issuer.
   Answer the browser with a small page telling the person to return to the
   application, then close the listener; close it too after a timeout.
6. **Redeem the code** at once with a form-encoded `POST` to the token endpoint
   carrying `grant_type=authorization_code`, `client_id`, `code`, the exact
   `redirect_uri` including its port, and `code_verifier`. Send no
   `Authorization` header and no `client_secret`: either is refused. A code is
   single-use and expires within 120 seconds.

An answer carrying `error` instead of `code` means: `access_denied`, the person
chose `Cancel`, declined at the provider, or could not be signed in;
`temporarily_unavailable`, AbandonAuth is busy and the attempt can start again
later; `invalid_request`, `invalid_scope` or `unsupported_response_type`, the
request itself is wrong; `server_error`, the attempt failed and can start again.
A request whose client or redirect cannot be proven is refused in the browser
and never reaches the listener.

## The tokens

A successful token response is a JSON object with `access_token`, `token_type`
`Bearer`, `expires_in` `900`, `id_token` and the granted `scope` in the order
`openid profile offline_access`; with `offline_access` it also has
`refresh_token` and `refresh_token_expires_in`. Do not cache it.

### Validating the ID token

The ID token identifies the person to the application. Accept it only when:

- its header is `alg` `RS256`, `typ` `JWT`, and a `kid` found in the `jwks_uri`
  key set, and the signature verifies with that key;
- `iss` equals the pinned issuer, and `aud` is a single string equal to the
  `client_id`;
- `sub` is a UUID in its canonical lower-case hyphenated spelling, and not the
  nil UUID `00000000-0000-0000-0000-000000000000`;
- `exp` is exactly 300 seconds after `iat`, and now is at or after `iat` and
  before `exp`, with **no clock tolerance**;
- `nonce` equals this attempt's nonce;
- it carries only `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce` and,
  with `profile`, `preferred_username`. Refuse `typ` `at+jwt` and any access
  token claim such as `scope`, `client_id`, `jti` or `auth_epoch`;
- its payload names no member twice and nothing follows the JSON object.

### Validating an access token on a resource server

A resource server the application calls validates the access token locally.
Accept it only when:

- its header is `alg` `RS256`, `typ` `at+jwt`, and a `kid` found in the
  `access_token_jwks_uri` key set, and the signature verifies with that key;
- it carries exactly `iss`, `sub`, `aud`, `client_id`, `scope`, `jti`,
  `auth_epoch`, `iat`, `nbf` and `exp`, and its payload names no member twice
  and nothing follows the JSON object;
- `iss` equals the pinned issuer; `aud` is one string equal to `client_id`,
  which is the expected application; `sub` is a canonical lower-case UUID other
  than the nil UUID; `client_id`, `jti` and `auth_epoch` are canonical
  lower-case UUIDs; `scope` holds the scopes the operation needs;
- `nbf` equals `iat`, `exp` is exactly 900 seconds later, and now is at or
  after `nbf` and before `exp`, with **no clock tolerance**.

A resource server does not compare `auth_epoch` with anything live.

A key set may be cached for up to five minutes. When a key is replaced,
tokens signed with the new key fail until the set is fetched again; fetch the
set again when a token names a `kid` the cached set does not hold, at most once
per five minutes.

### Withdrawn tokens stay valid elsewhere for up to fifteen minutes

AbandonAuth's own refresh and UserInfo stop accepting a grant at once when it is
revoked, when the application or person is deleted, or when the operator
rotates AbandonAuth's authority. A resource server validating an access token
locally learns of none of these and keeps accepting the token until it
expires, **up to fifteen minutes after it was withdrawn**. An operation that
cannot tolerate that window must not rely on local validation; it can ask the
UserInfo endpoint instead, which refuses a withdrawn token immediately.

Because validators allow no clock tolerance, any error in a clock adds directly
to that window. Run AbandonAuth and every resource server on UTC clocks
synchronized to a common time source. Before relying on the fifteen-minute
bound, measure the offset between them with a canary and confirm it is below one
second, and alert when an observed offset reaches one second.

## Who the person is

`sub` is the person's **AbandonAuth user identifier**: a UUID in its canonical
lower-case hyphenated spelling, never the nil UUID. It is the only machine
identifier for the person; there is no `user_id` claim. Key the application's
own records by `sub`, compared exactly as the string it is.

`sub` is the same at every application the person signs in to, and it is the
same value a confidential application reads as the `sub` of its user token.
Applications can therefore recognise the same person across one another, which
is what lets a service with an installed application and a server-side one bind
both to one record; it also means any two applications can correlate the
person. AbandonAuth does not link provider accounts: a sign-in with a provider
account that is not the one behind that AbandonAuth user is another user with
another `sub`. `sub` is released under `openid` alone and never needs
`profile`.

`preferred_username` is released only with `profile`. It is not an identifier;
use it only for display.

`GET` the UserInfo endpoint with the access token as a `Bearer` credential to
read the current claims. It answers `401` with `WWW-Authenticate: Bearer
error="invalid_token"` for any token it does not accept.

## Staying signed in

`offline_access` issues an opaque refresh token. Store it only in the operating
system's secure credential storage, never in a plain file, a log or a command
line. Each refresh token expires 30 days after it is issued, and the session
ends 90 days after sign-in whatever happens.

Refresh with a form-encoded `POST` to the token endpoint carrying
`grant_type=refresh_token`, `client_id` and `refresh_token`, and optionally a
narrower `scope` that still contains `openid`. A refresh never widens the
grant, and narrowing away `offline_access` ends the session.

Refresh tokens rotate: every refresh returns a replacement and consumes the
token presented. Presenting a consumed token again revokes the whole session.
So:

- **serialize refreshes**: never refresh twice at once with one token, from any
  thread or process;
- **commit the replacement first**: write the new refresh token to secure
  storage before discarding the one presented.

One person can hold ten active sessions with one application. Signing in
again for an eleventh ends the least recently created; its refresh token then
answers `invalid_grant`, and the application must send the person through the
browser again.

A refresh token, code or verifier that answers `invalid_grant` will never work:
discard it and start a new sign-in. `invalid_client` means the application's
registration is gone.

## Signing out

`POST` to the revocation endpoint a form with `client_id` and `token`: the
refresh token, the access token, or one after the other. Revoking a refresh
token ends the session at once. Revoking an access token makes AbandonAuth's
UserInfo refuse it at once; a resource server validating it locally still
accepts it until it expires. The answer is an empty `200` whether or not
anything was revoked, so delete the local copies either way. `token_type_hint`
is accepted and ignored. A `503` `temporarily_unavailable` answer means the
token was **not** revoked: AbandonAuth holds a fixed ceiling of a thousand
unexpired revoked access tokens per person and application, and the request
can be retried once some have expired.
