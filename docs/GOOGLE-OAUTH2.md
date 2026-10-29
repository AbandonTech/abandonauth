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
