# AbandonAuth website

The administration and login site. It is a Nuxt application that talks to the
AbandonAuth API through the `/api` prefix on its own origin, so the browser
session cookie the API sets is returned on every call.

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

`npm run dev` proxies `/api` to `ABANDON_AUTH_URL`. A deployment serves the site
and the API from one origin instead, with the reverse proxy stripping `/api`.

## Settings

| Name | Used for |
| --- | --- |
| `ABANDON_AUTH_URL` | Where `/api` calls are sent |
| `ABANDON_AUTH_DEVELOPER_APP_ID` | The application this site signs people in to |

Both are read at build time.
