# AbandonAuth website

The administration and login site. It is a Nuxt application that talks to the
AbandonAuth API at `/api` on its own origin, so the browser session cookie the
API sets is returned on every call. `/api` is the API's own route root: the
site forwards the whole path there and receives the answer for it.

npm and `package-lock.json` are canonical. Do not add a lockfile for another
package manager.

## Commands

```bash
npm install
npm run dev      # http://localhost:3000
npm test
npm run build
npm run preview
```

`npm run dev` forwards `/api` to `ABANDON_AUTH_URL`. A deployment serves the
site and the API from one origin instead. Either way the API receives the path
the browser asked for, so a call to `/api/me` here is a call to `/api/me`
there.

The development forwarder is mounted on `/api` and hands on the path with that
root already removed, so it is pointed at the address plus the root; the site's
own server route forwards `event.path` whole. Both end at the same address.

## Settings

| Name | Used for |
| --- | --- |
| `ABANDON_AUTH_URL` | Where `/api` calls are sent |
| `ABANDON_AUTH_SITE_URL` | The origin a browser reaches this site on, which the sign-in callback is built from |
| `ABANDON_AUTH_DEVELOPER_APP_ID` | The application this site signs people in to |

All three are read at build time, from this directory's own `.env` rather than
the one at the repository root. A deployment passes them as build arguments.

The sign-in callback is `ABANDON_AUTH_SITE_URL` plus `/api/ui`, and the API
matches it byte for byte against what the application registered, so changing
that origin means re-registering the callback as well as rebuilding. It is
built on the site's origin, not the API's: the session cookie belongs to the
site, and a browser returned straight to the API would carry none of it.
