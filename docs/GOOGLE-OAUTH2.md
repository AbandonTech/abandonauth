# Google OAuth2 Setup

###  1. Goto [Google Cloud Console - Credentials](https://console.cloud.google.com/apis/credentials)

### 2. Create a New Application

Pick a project or create one, then `Create Credentials` and `OAuth client ID`.
Google asks you to configure the consent screen first if the project has none.

Note: the client type must be `Web application`. The other types cannot be given
a redirect URI, and this service always sends one.

### 3. Add details

Under `Authorized redirect URIs`, add the callback below. Google matches it
exactly, and so does AbandonAuth, so the two must agree byte for byte.

Nothing needs to be added under `Authorized JavaScript origins`: the browser is
redirected to Google rather than calling it from a page.

### 4. Get Client ID and Secrets

Google shows the client ID and secret once the client is created. The secret can
be revealed again later from the same page.

### 5. Fill `.env` file

```dotenv
# Google Application Details for OAuth2
GOOGLE_CLIENT_ID=<Client ID in step 4>
GOOGLE_CLIENT_SECRET=<Client Secret in step 4>
GOOGLE_CALLBACK=http://localhost:3000/api/google
```

Note that Google's callback is `GOOGLE_CALLBACK`, without the
`ABANDON_AUTH_` prefix that Discord's and GitHub's carry.

Register that same address with Google in step 3, exactly. A sign-in starts at
the site on port 3000, which is where the cookie binding the attempt to your
browser is set, so a redirect back to the API's own port carries no such cookie
and the login cannot be matched to one that was started.

There is no setting holding a provider's authorization URL. The API builds it
from the client ID and callback above, so that the address, the scopes and the
per-attempt state are decided in one place.

Google is the one provider that returns an identity token as well as an access
token, and this service checks it: the issuer, the audience and authorized
party, an RS256 signature against Google's published keys, the nonce it was
started with, and the clock claims. Its endpoints are compiled in and are
compared against Google's discovery document rather than taken from it, so a
discovery response naming other addresses is refused rather than followed.
