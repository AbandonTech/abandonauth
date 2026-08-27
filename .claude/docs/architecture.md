# Architecture

## Runtime

AbandonAuth consists of a FastAPI API, a Nuxt 3 website, and PostgreSQL. Prisma
Client Python is the persistence layer. `compose.yml` runs all three services
for local development.

The API app in `src/api/abandonauth/main.py` configures CORS, mounts routers,
and connects the shared Prisma client during application startup. Routes use
Pydantic DTOs and generally call generated Prisma model clients directly.

The website serves login and developer-application administration. Its Nitro
catch-all route proxies `/api/**` requests to the configured API. Client code
currently reads the `Authorization` cookie and supplies bearer tokens to API
requests; this is not a server-side session boundary.

## Identity flows

### Provider login

1. The website constructs a Discord or GitHub provider authorization URL.
2. Provider callbacks reach `routers/ui.py` with an authorization code and
   state containing an application ID and callback URI.
3. The callback verifies that the URI appears on the developer application.
4. The provider helper exchanges the code, fetches provider identity data, and
   finds or creates a local user/provider account.
5. The API creates a short-lived exchange JWT and redirects to the registered
   application callback with that credential.
6. `/login` authenticates the developer application and converts the exchange
   credential to a long-lived JWT for that application's audience.

Google uses a separate flow in `routers/google.py`; it does not currently use
the same developer application callback verification.

### Internal UI session

`/ui` exchanges a code using AbandonAuth's own developer application
credentials, validates the resulting JWT through `/me`, and writes it to an
`Authorization` cookie. The frontend uses that cookie as a bearer credential.

### Developer applications

Authenticated users create developer applications and receive a one-time
plaintext refresh token whose hash is stored. Applications register callback
URI strings and can exchange their refresh token for a developer application
JWT. User ownership checks are implemented in router functions.

## Persistence

The schema and migration history live under `src/api/prisma/`. Generated
Prisma client code is dependency output, not source. Schema changes require a
new migration that is reviewed for existing-data and rollback behavior; never
use production `prisma db push`.

## Boundaries

- Provider responses and all browser input are untrusted.
- OAuth state and redirect values remain untrusted after round trips through a
  provider.
- JWT claims are untrusted until signature, algorithm, issuer, audience, token
  type, expiration, and required claims are validated.
- Developer application credentials, user tokens, exchange tokens, provider
  tokens, and browser sessions are distinct credential classes.
- Debug configuration is a deployment security boundary and must fail closed.
